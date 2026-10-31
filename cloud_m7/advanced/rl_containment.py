"""
Track 3: simulated tabular Q-learning containment policy.
Adapted from DharshiniPES/cloud-m7 (23ba5ed). No enforcement is executed.
Formulates multi-tier containment as a Markov Decision Process (MDP) and trains
a Q-Learning / Policy agent that balances containment speed against SLA collateral disruption.
"""

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class RlContainmentStep:
    state_id: int
    state_name: str
    action_id: int
    action_name: str
    reward: float
    next_state_name: str
    containment_efficacy_pct: float
    collateral_disruption_index: float
    q_value: float


@dataclass
class RlTrainingSummary:
    episodes_trained: int
    final_cumulative_reward: float
    convergence_episode: int | None
    optimal_policy: Dict[str, str]
    action_distribution: Dict[str, float]
    simulation_trajectory: List[RlContainmentStep]


class AutonomousRlContainmentAgent:
    """
    Q-Learning autonomous containment agent for multi-tier active defense.
    State Space: [Nominal, Edge Intrusion, Fog Pivot, Cloud Exfiltration Risk, Contained]
    Action Space: [NOOP, Rate Limit, Freeze cgroup PID, Drop Choke Socket, Revoke IAM, Total Isolate]
    """

    STATES = {
        0: "S0: NOMINAL_BENIGN",
        1: "S1: EDGE_SENSOR_INTRUSION",
        2: "S2: FOG_GATEWAY_PIVOT",
        3: "S3: CLOUD_EXFILTRATION_RISK",
        4: "S4: ATTACK_CONTAINED_STABLE",
    }

    ACTIONS = {
        0: "NOOP (Monitor Only)",
        1: "RATE_LIMIT_EGRESS (30% Throttle)",
        2: "FREEZE_CGROUP_PID (Edge Process)",
        3: "DROP_CHOKE_SOCKET (Fog Articulation Cut)",
        4: "REVOKE_CLOUD_IAM (Cloud Session Invalidation)",
        5: "TOTAL_SUBNET_ISOLATE (High Collateral Blast Radius)",
    }

    def __init__(self, alpha: float = 0.25, gamma: float = 0.95, epsilon: float = 0.15, random_seed: int = 42):
        self.rng = random.Random(random_seed)
        if not 0 < alpha <= 1 or not 0 <= gamma < 1 or not 0 <= epsilon <= 1:
            raise ValueError('Invalid learning parameters')
        self.alpha = alpha  # Learning rate
        self.gamma = gamma  # Discount factor
        self.epsilon = epsilon  # Exploration rate
        self.num_states = len(self.STATES)
        self.num_actions = len(self.ACTIONS)

        # Initialize Q-Table [num_states x num_actions]
        self.q_table = [[0.0 for _ in range(self.num_actions)] for _ in range(self.num_states)]

    def compute_reward(self, state: int, action: int) -> Tuple[float, int, float, float]:
        """
        Calculates environment reward:
        Hand-authored reward table; efficacy and disruption are model assumptions.
        Returns: (reward, next_state, containment_efficacy, collateral_disruption)
        """
        # S0: Nominal
        if state == 0:
            if action == 0:
                return (10.0, 0, 100.0, 0.0)
            else:
                return (-30.0, 0, 100.0, 0.4)  # Penalty for intervening when benign

        # S1: Edge Intrusion
        elif state == 1:
            if action == 2:  # Freeze cgroup PID
                return (85.0, 4, 95.0, 0.05)  # Surgical stop at Edge
            elif action == 3:  # Drop choke socket
                return (40.0, 4, 85.0, 0.2)
            elif action == 1:  # Rate limit
                # A later reward must not make deliberately allowing a pivot
                # preferable to containing the attack at the edge.
                return (-50.0, 2, 40.0, 0.05)
            elif action == 5:  # Total isolate
                return (-20.0, 4, 100.0, 0.85)  # Severe collateral damage penalty
            else:
                return (-50.0, 2, 0.0, 0.0)  # NOOP lets attack progress

        # S2: Fog Pivot (The Key Choke Point)
        elif state == 2:
            if action == 3:  # Drop choke socket (Cut-Vertex!)
                return (120.0, 4, 100.0, 0.1)  # Dominant optimal intervention at Fog!
            elif action == 2:  # Freeze edge process
                return (-15.0, 3, 30.0, 0.1)  # Too late, fog is already compromised!
            elif action == 4:  # Revoke IAM
                return (30.0, 4, 75.0, 0.2)
            elif action == 5:  # Total isolate
                return (-10.0, 4, 100.0, 0.9)  # High collateral disruption
            else:
                return (-70.0, 3, 0.0, 0.0)  # Attack reaches Cloud!

        # S3: Cloud Exfiltration Risk
        elif state == 3:
            if action == 4:  # Revoke IAM
                return (80.0, 4, 95.0, 0.25)
            elif action == 3:  # Drop choke socket
                return (60.0, 4, 85.0, 0.15)
            elif action == 5:  # Total isolate
                return (30.0, 4, 100.0, 0.95)
            else:
                return (-120.0, 3, 0.0, 0.0)  # Disaster: Exfiltration succeeds!

        # S4: Contained Stable
        else:
            return (15.0, 4, 100.0, 0.0)

    def train_agent(self, episodes: int = 150, initial_state: int = 1) -> RlTrainingSummary:
        """Runs Q-Learning policy training across simulated multi-tier breach episodes."""
        episode_rewards = []
        if episodes < 0 or initial_state not in self.STATES:
            raise ValueError('Nonnegative episodes and a valid initial state required')
        convergence_ep = None
        stable_episodes = 0
        action_counts = {name: 0 for name in self.ACTIONS.values()}

        for ep in range(episodes):
            largest_change = 0.0
            for training_state in [0, 1, 2, 3]:
                curr_state = training_state
                cum_reward = 0.0

                for step in range(6):
                    # Epsilon-greedy action selection
                    if self.rng.random() < self.epsilon:
                        action = self.rng.randint(0, self.num_actions - 1)
                    else:
                        action = max(range(self.num_actions), key=lambda a: self.q_table[curr_state][a])

                    reward, next_state, _, _ = self.compute_reward(curr_state, action)
                    action_counts[self.ACTIONS[action]] += 1
                    cum_reward += reward

                    # Bellman Equation Update:
                    # Q(s, a) <- Q(s, a) + alpha * [r + gamma * max_a' Q(s', a') - Q(s, a)]
                    best_next_q = 0.0 if next_state == 4 else max(self.q_table[next_state])
                    td_target = reward + self.gamma * best_next_q
                    td_error = td_target - self.q_table[curr_state][action]
                    self.q_table[curr_state][action] += self.alpha * td_error
                    largest_change = max(largest_change, abs(self.alpha * td_error))

                    curr_state = next_state
                    if curr_state == 4:
                        break

                episode_rewards.append(cum_reward)
            stable_episodes = stable_episodes + 1 if largest_change < 0.001 else 0
            if stable_episodes >= 5 and convergence_ep is None:
                convergence_ep = ep + 1

        # Extract optimal policy for each state
        optimal_policy = {}
        for s in range(self.num_states):
            best_a = max(range(self.num_actions), key=lambda a: self.q_table[s][a])
            optimal_policy[self.STATES[s]] = self.ACTIONS[best_a]

        # Execute optimal simulation trajectory for dashboard visualization
        trajectory = []
        eval_state = initial_state
        for _ in range(0 if initial_state == 4 else 4):
            best_a = max(range(self.num_actions), key=lambda a: self.q_table[eval_state][a])
            reward, next_s, eff, cdi = self.compute_reward(eval_state, best_a)
            trajectory.append(
                RlContainmentStep(
                    state_id=eval_state,
                    state_name=self.STATES[eval_state],
                    action_id=best_a,
                    action_name=self.ACTIONS[best_a],
                    reward=reward,
                    next_state_name=self.STATES[next_s],
                    containment_efficacy_pct=eff,
                    collateral_disruption_index=cdi,
                    q_value=round(self.q_table[eval_state][best_a], 2),
                )
            )
            eval_state = next_s
            if eval_state in (0, 4):
                break

        total_actions = sum(action_counts.values())
        action_distribution = {name: count / total_actions if total_actions else 0.0
                               for name, count in action_counts.items()}

        return RlTrainingSummary(
            episodes_trained=episodes,
            final_cumulative_reward=round(sum(episode_rewards[-10:]) / max(len(episode_rewards[-10:]), 1), 1),
            convergence_episode=convergence_ep,
            optimal_policy=optimal_policy,
            action_distribution=action_distribution,
            simulation_trajectory=trajectory,
        )

    def get_dashboard_summary(self, initial_state: int = 0) -> Dict[str, Any]:
        """Provides formatted JSON telemetry for the Node.js frontend."""
        summary = self.train_agent(episodes=120, initial_state=initial_state)
        return {
            "mode": "simulated_policy",
            "state_source": "Supplied event labels and tiers, not a learned incident detector",
            "initial_state": self.STATES[initial_state],
            "enforcement_executed": False,
            "reward_model": "Hand-authored five-state environment; efficacy is a model assumption",
            "episodes_trained": summary.episodes_trained,
            "convergence_episode": summary.convergence_episode,
            "final_reward": summary.final_cumulative_reward,
            "optimal_policy": summary.optimal_policy,
            "action_distribution": summary.action_distribution,
            "simulation_trajectory": [
                {
                    "state": step.state_name,
                    "action": step.action_name,
                    "reward": step.reward,
                    "next_state": step.next_state_name,
                    "containment_pct": step.containment_efficacy_pct,
                    "cdi": step.collateral_disruption_index,
                    "q_val": step.q_value,
                }
                for step in summary.simulation_trajectory
            ],
        }
