/* 
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the 
 * Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
 *
 * It is based on the LEDBAT implementation by Silvio Valenti
 *
 * Updated by Qian Li to conform to LEDBAT++ draft version 01
 * 
 */

#include <linux/module.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/time64.h>

// init cwnd can be set with: sudo ip route add dst_ip/24 via next_hop_ip dev eth0 initcwnd 2 //

#define MIN_CWND 2
// length of base history in minutes
#define BASE_HISTORY_LEN 10
// length of current delay filter in number of samples
#define DELAY_FILTER_LEN 4
// target delay in ms
#define TARGET 60
// decrease constant
#define C 1
#define MAX_RTT 0xffffffff
 
struct circular_buffer {
	u32 *buffer;
	u8 first;
	u8 last;
	u8 min;
	u8 len;
};

struct ledbatpp {
	struct circular_buffer base_delay_history;
	struct circular_buffer cur_delay_filter;
	u64 cur_sld_start; // current slow down start time in ms
	u64 schd_sld_start; // scheduled slow down start time in ms
	u64 minute_start; // last rollover in ms
	u32 undo_cwnd; // storing latest cwnd 
    u32 snd_nxt; // sequence number of the next packet being sent at the beginning of cwnd reduction. used to mark RTT
    u32 dec_quota; // max allowed cwnd reduction per RTT
    s32 accrued_dec_bytes; // accrued window decrease in the unit of bytes, it can be negative sometimes
    bool can_ss; // if the flow should do slow start or CA
};

static int init_circular_buffer(struct circular_buffer *cb, u16 len)
{
	u32 *buffer = kzalloc(len * sizeof(u32), GFP_KERNEL);
	if (buffer == NULL)
		return 1;
	cb->len = len;
	cb->buffer = buffer;
	cb->first = 0;
	cb->last = 0;
	cb->min = 0;
	return 0;
}

static void tcp_ledbatpp_release(struct sock *sk)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	
	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;
	
	kfree(ledbatpp->cur_delay_filter.buffer);
	kfree(ledbatpp->base_delay_history.buffer);
}

static void tcp_ledbatpp_init(struct sock *sk)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if(init_circular_buffer(&ledbatpp->base_delay_history, BASE_HISTORY_LEN + 1))
		return;
	if(init_circular_buffer(&ledbatpp->cur_delay_filter, DELAY_FILTER_LEN + 1))
		return;

    ledbatpp->minute_start = 0;
	ledbatpp->cur_sld_start = 0;
	ledbatpp->schd_sld_start = 0;
	ledbatpp->snd_nxt = 0;
	ledbatpp->dec_quota = 0;
	ledbatpp->accrued_dec_bytes = 0;
    ledbatpp->undo_cwnd = tp->snd_cwnd;
	ledbatpp->can_ss = true;
}

typedef u32 (*filter_function) (struct circular_buffer *);

// implements the filter_function above
static u32 min_filter(struct circular_buffer *cb)
{
	if (cb->first == cb->last) // empty buffer
		return MAX_RTT;
	return cb->buffer[cb->min];
}

static u32 get_current_delay(struct ledbatpp *ledbatpp, filter_function filter)
{
	return filter(&ledbatpp->cur_delay_filter);
}

static u32 get_base_delay(struct ledbatpp *ledbatpp)
{
	return min_filter(&ledbatpp->base_delay_history);
}

// invoked at the time of loss, used by both duplicate ack and rto losses
static u32 tcp_ledbatpp_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);

	return max_t(u32, tp->snd_cwnd >> 1U, MIN_CWND);
}

// invoked after loss recovery
static void tcp_ledbatpp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;
	switch (ev) {
	case CA_EVENT_CWND_RESTART: // after idle, cwnd is restarted
		tp->snd_cwnd_cnt = 0;
		ledbatpp->accrued_dec_bytes = 0;
		ledbatpp->snd_nxt = 0;
		ledbatpp->dec_quota = 0;
		ledbatpp->can_ss = true;
		break;
	case CA_EVENT_COMPLETE_CWR: // after fast retransmit and fast recovery
		tp->snd_cwnd_cnt = 0;
		ledbatpp->accrued_dec_bytes = 0;
		ledbatpp->snd_nxt = 0;
		ledbatpp->dec_quota = 0;
		ledbatpp->can_ss = false;
		break;
	case CA_EVENT_LOSS: // rto timer timeout
		tp->snd_cwnd_cnt = 0;
		ledbatpp->accrued_dec_bytes = 0;
		ledbatpp->snd_nxt = 0;
		ledbatpp->dec_quota = 0;
		ledbatpp->can_ss = true;
		break;
	default:
		break;
	}
}

static bool ledbatpp_ai(struct sock *sk, u32 w, u32 acked)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	u32 cwnd = 0, delta, diff, ca = false;
    
	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		delta = tp->snd_cwnd_cnt / w;
        cwnd = tp->snd_cwnd + delta;
        tp->snd_cwnd_cnt -= delta * w;
        if (ledbatpp->can_ss && tcp_in_slow_start(tp) && cwnd > tp->snd_ssthresh) {
            diff = cwnd - tp->snd_ssthresh;
            tp->snd_cwnd_cnt += diff * w;
            ca = true;
            tp->snd_cwnd = min3(cwnd, tp->snd_ssthresh, tp->snd_cwnd_clamp);
        } else {
        	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
        }
        ledbatpp->undo_cwnd = tp->snd_cwnd;
	}
	
    return ca;
}

// ledbat++'s own slow start
static bool ledbatpp_slow_start(struct sock *sk, u32 acked, u32 inversed_gain, u32 queue_delay, u32 base_delay)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ms;
	bool ca;
	
	if (tcp_in_initial_slowstart(tp) && queue_delay > (TARGET * 3 >> 2)) { // quit initial slow start due to delay is large
		tp->snd_ssthresh = tp->snd_cwnd;
		ledbatpp->can_ss = false;
		// schedule the initial slow down
		now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
		ledbatpp->schd_sld_start = now_ms + (tp->srtt_us >> 2) / USEC_PER_MSEC;
        tp->snd_cwnd_cnt += acked;
		return true; 
	}
	
    ca = ledbatpp_ai(sk, inversed_gain, acked);
	
	// end of slow start, update slow down start time
	if (tp->snd_cwnd >= tp->snd_ssthresh) { // quit slow start due to ssthresh reached
		ledbatpp->can_ss = false;
		now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
		if (tcp_in_initial_slowstart(tp)) {
			ledbatpp->schd_sld_start = now_ms + (tp->srtt_us >> 2) / USEC_PER_MSEC;
		} else { // end of non-initial slow start 
			ledbatpp->schd_sld_start = now_ms + (now_ms - ledbatpp->cur_sld_start) * 9;
			ledbatpp->cur_sld_start = 0;
			ledbatpp->accrued_dec_bytes = 0;
			ledbatpp->snd_nxt = 0;
			ledbatpp->dec_quota = 0;
		} 
	} 
    return ca;
}

static void ledbatpp_decrease_cwnd(struct sock * sk, int off_target, u32 inversed_gain) 
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int dec_p, allw_dec_p;
	
	ledbatpp->accrued_dec_bytes += (-off_target * C * (int)tp->snd_cwnd * (int)inversed_gain - TARGET) * (int)tp->mss_cache / TARGET / (int)tp->snd_cwnd / (int)inversed_gain;
	dec_p = ledbatpp->accrued_dec_bytes / (int)tp->mss_cache;
	ledbatpp->accrued_dec_bytes -= dec_p * (int)tp->mss_cache;
	if (dec_p <= ledbatpp->dec_quota){
		allw_dec_p = dec_p;
		ledbatpp->dec_quota -= dec_p;
	} else {
		allw_dec_p = ledbatpp->dec_quota;
		ledbatpp->dec_quota = 0;
	}
	tp->snd_cwnd = max_t(int, (int)tp->snd_cwnd - allw_dec_p, MIN_CWND);
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
	ledbatpp->undo_cwnd = tp->snd_cwnd;
}

static void tcp_ledbatpp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ms;
	u32 current_delay, base_delay, queue_delay, inversed_gain;
    int off_target;
    bool ca;
	
	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;
	
	if (!tcp_is_cwnd_limited(sk))
		return;
	
	if ((base_delay = get_base_delay(ledbatpp)) == MAX_RTT) // base_delay not available
		return;
	
	if((current_delay = get_current_delay(ledbatpp, &min_filter)) == MAX_RTT) // current delay not available
		return;

	now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
	
	if (ledbatpp->cur_sld_start) { // in slow down
		if (now_ms - ledbatpp->cur_sld_start <= (tp->srtt_us >> 2) / USEC_PER_MSEC) { // stay in slow down for 2 RTTs
			return;
		} else { // quit slow down
			if (tp->snd_cwnd >= tp->snd_ssthresh) { // subsequent slow start quited with loss
				ledbatpp->can_ss = false;
				ledbatpp->schd_sld_start = now_ms + (now_ms - ledbatpp->cur_sld_start) * 9;
				ledbatpp->cur_sld_start = 0;
				ledbatpp->accrued_dec_bytes = 0;
				ledbatpp->snd_nxt = 0;
				ledbatpp->dec_quota = 0;
				tp->snd_cwnd_cnt = 0;
			} else { // do slow start
			}
		}
	} else { // not in slow down
		if (ledbatpp->schd_sld_start && now_ms >= ledbatpp->schd_sld_start) { // should slow down
			tp->snd_ssthresh = tp->snd_cwnd;
			tp->snd_cwnd = MIN_CWND;
			ledbatpp->undo_cwnd = tp->snd_cwnd;
			ledbatpp->cur_sld_start = now_ms; 
			ledbatpp->schd_sld_start = 0;
			ledbatpp->can_ss = true;
			tp->snd_cwnd_cnt = 0;
			return;
		}
		if (!ledbatpp->schd_sld_start && tp->snd_cwnd >= tp->snd_ssthresh) { // initial slow start quited with loss
			ledbatpp->can_ss = false;
			ledbatpp->schd_sld_start = now_ms + (tp->srtt_us >> 2) / USEC_PER_MSEC;
			ledbatpp->cur_sld_start = 0;
			ledbatpp->accrued_dec_bytes = 0;
			ledbatpp->snd_nxt = 0;
			ledbatpp->dec_quota = 0;
			tp->snd_cwnd_cnt = 0;
		}
	}

	queue_delay = current_delay - base_delay;
	off_target = TARGET - queue_delay;
	inversed_gain = min_t(u32, 16, DIV_ROUND_UP(2 * TARGET, base_delay)); 
	
	if (tcp_in_slow_start(tp) && ledbatpp->can_ss) { // do slow start 
        ca = ledbatpp_slow_start(sk, acked, inversed_gain, queue_delay, base_delay);
		if(!ca) {
            return;
		} else {
            acked = 0; // all acked packets have been added to tp->snd_cwnd_cnt
		}
	}

	// congestion avoidance
	if (off_target >= 0) { // increase cwnd
        ledbatpp_ai(sk, tp->snd_cwnd * inversed_gain, acked);
        ledbatpp->accrued_dec_bytes = 0;
        ledbatpp->snd_nxt = 0;
        ledbatpp->dec_quota = 0;
	} else { // decrease cwnd
		if (ack >= ledbatpp->snd_nxt) { // a new rtt has began, update decrease quota, etc.
			ledbatpp->snd_nxt = tp->snd_nxt;
			ledbatpp->dec_quota = tp->snd_cwnd >> 1;
			ledbatpp->accrued_dec_bytes = 0;
		}
		ledbatpp_decrease_cwnd(sk, off_target, inversed_gain);
		tp->snd_cwnd_cnt = 0;
	}
}

static void add_delay(struct circular_buffer *cb, u32 rtt)
{
	u8 i;

	if (cb->last == cb->first) {
		/*buffer is empty */
		cb->buffer[cb->last] = rtt;
		cb->min = cb->last;
		cb->last++;
		return;
	}

	/*insert the new delay */
	cb->buffer[cb->last] = rtt;
	/* update the min if it is the case */
	if (rtt < cb->buffer[cb->min])
		cb->min = cb->last;

	/* increase the last pointer */
	cb->last = (cb->last + 1) % cb->len;

	if (cb->last == cb->first) {
		if (cb->min == cb->first) {
			/* Discard the min, search a new one */
			cb->min = i = (cb->first + 1) % cb->len;
			while (i != cb->last) {
				if (cb->buffer[i] < cb->buffer[cb->min])
					cb->min = i;
				i = (i + 1) % cb->len;
			}
		}
		/* move the first */
		cb->first = (cb->first + 1) % cb->len;
	}
}

static void update_current_delay(struct ledbatpp *ledbatpp, u32 rtt)
{
	add_delay(&(ledbatpp->cur_delay_filter), rtt);
}

static void update_base_delay(struct ledbatpp *ledbatpp, u32 rtt)
{
	struct circular_buffer *cb = &(ledbatpp->base_delay_history);
	u32 last, now_ms = div_u64(tcp_clock_ns(), NSEC_PER_MSEC);
	
	if (ledbatpp->minute_start == 0)
		ledbatpp->minute_start = now_ms;

	if (cb->last == cb->first) {
		/* empty circular buffer */
		add_delay(cb, rtt);
		return;
	}

	if (now_ms - ledbatpp->minute_start > 60 * MSEC_PER_SEC) {
		/* we have finished a minute */
		ledbatpp->minute_start = now_ms;
		add_delay(cb, rtt);
	} else {
		/* update the last value and the min if it is the case */
		last = (cb->last + cb->len - 1) % cb->len;
		if (rtt < cb->buffer[last]) {
			cb->buffer[last] = rtt;
			if (rtt < cb->buffer[cb->min])
				cb->min = last;
		}
	}
}

static void tcp_ledbatpp_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 rtt_ms;
	
	if(!ledbatpp->base_delay_history.buffer) // not initialized properly
		return;

	if (sample->rtt_us <= 0) 
		return;
	
	rtt_ms = sample->rtt_us / USEC_PER_MSEC;
	update_current_delay(ledbatpp, rtt_ms);
	update_base_delay(ledbatpp, rtt_ms);
}

static u32 tcp_ledbatpp_undo_cwnd(struct sock *sk)
{
	struct ledbatpp *ledbatpp = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if(!ledbatpp->base_delay_history.buffer) { // not initialized properly
		return max(tp->snd_cwnd, tp->prior_cwnd);
	}
	
	return ledbatpp->undo_cwnd;
}

static struct tcp_congestion_ops tcp_ledbatpp = {
	.init = tcp_ledbatpp_init,
	.ssthresh = tcp_ledbatpp_ssthresh,
	.cong_avoid = tcp_ledbatpp_cong_avoid,
	.pkts_acked = tcp_ledbatpp_pkts_acked,
	.undo_cwnd = tcp_ledbatpp_undo_cwnd,
	.cwnd_event = tcp_ledbatpp_cwnd_event,
	.release = tcp_ledbatpp_release,

	.owner = THIS_MODULE,
	.name = "ledbatpp"
};

static int __init tcp_ledbatpp_register(void)
{
	BUILD_BUG_ON(sizeof(struct ledbatpp) > ICSK_CA_PRIV_SIZE);
	
	return tcp_register_congestion_control(&tcp_ledbatpp);
}

static void __exit tcp_ledbatpp_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_ledbatpp);
}

module_init(tcp_ledbatpp_register);
module_exit(tcp_ledbatpp_unregister);

MODULE_AUTHOR("Qian Li");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Ledbat Plus Plus");
