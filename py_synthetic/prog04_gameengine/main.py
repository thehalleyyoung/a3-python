"""Game engine - main module."""
from player import Player, create_player
from game_logic import move_player, check_collision, calculate_damage


class GameEngine:
    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.players = []
        self.entities = []
    
    def add_player(self, name: str) -> Player:
        player = create_player(name, len(self.players))
        self.players.append(player)
        return player
    
    def get_player(self, player_id: int) -> Player:
        """Get player by ID."""
        # BUG: BOUNDS - no check
        return self.players[player_id]
    
    def update(self):
        """Update game state."""
        for player in self.players:
            # BUG: NULL_PTR - player could have None position after death
            if player.position.x < 0:
                player.position.x = 0
    
    def calculate_average_score(self) -> float:
        """Calculate average player score."""
        total = sum(p.score for p in self.players)
        # BUG: DIV_ZERO - if no players
        return total / len(self.players)


def run_game_loop(engine: GameEngine, turns: int):
    """Run main game loop."""
    for turn in range(turns):
        engine.update()
        # Process each player's turn
        for i, player in enumerate(engine.players):
            move_player(player, i % 4)  # Direction based on turn


def get_leaderboard(players: list, rank: int) -> Player:
    """Get player at specific rank."""
    sorted_players = sorted(players, key=lambda p: p.score, reverse=True)
    # BUG: BOUNDS - rank could be out of range
    return sorted_players[rank]
