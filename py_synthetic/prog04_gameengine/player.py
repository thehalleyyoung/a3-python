"""Player model and utilities."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Position:
    x: int
    y: int


@dataclass
class Player:
    id: int
    name: str
    position: Optional[Position]
    health: int = 100
    score: int = 0
    is_alive: bool = True
    
    def take_damage(self, amount: int):
        self.health -= amount
        if self.health <= 0:
            self.is_alive = False
            self.position = None  # Dead players have no position
    
    def heal(self, amount: int):
        self.health = min(100, self.health + amount)
    
    def add_score(self, points: int):
        self.score += points


def create_player(name: str, player_id: int) -> Player:
    """Create a new player at origin."""
    return Player(
        id=player_id,
        name=name,
        position=Position(0, 0)
    )


def get_player_position(player: Player) -> tuple:
    """Get player position as tuple."""
    # BUG: NULL_PTR - position could be None
    return (player.position.x, player.position.y)


def get_player_from_list(players: list, index: int) -> Player:
    """Get player from list by index."""
    # BUG: BOUNDS
    return players[index]


def calculate_health_percent(player: Player, max_health: int) -> float:
    """Calculate health as percentage."""
    # BUG: DIV_ZERO - max_health could be 0
    return (player.health / max_health) * 100


def safe_get_position(player: Player) -> tuple:
    """Safely get player position."""
    if player.position is None:
        return (0, 0)  # Safe: default value
    return (player.position.x, player.position.y)
