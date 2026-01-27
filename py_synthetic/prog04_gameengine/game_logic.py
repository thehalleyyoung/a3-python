"""Game logic utilities."""
from player import Player, Position


def move_player(player: Player, direction: int):
    """Move player in direction (0=up, 1=right, 2=down, 3=left)."""
    # BUG: NULL_PTR - position could be None
    if direction == 0:
        player.position.y -= 1
    elif direction == 1:
        player.position.x += 1
    elif direction == 2:
        player.position.y += 1
    elif direction == 3:
        player.position.x -= 1


def check_collision(p1: Player, p2: Player) -> bool:
    """Check if two players collide."""
    # BUG: NULL_PTR - positions could be None
    return (p1.position.x == p2.position.x and 
            p1.position.y == p2.position.y)


def calculate_damage(base: int, multiplier: float, defense: int) -> int:
    """Calculate final damage."""
    # BUG: DIV_ZERO - defense could be 0 (actually this is subtraction, no bug)
    raw_damage = int(base * multiplier)
    return max(0, raw_damage - defense)


def get_distance(p1: Position, p2: Position) -> float:
    """Calculate distance between positions."""
    # BUG: NULL_PTR - positions could be None passed in
    dx = p2.x - p1.x
    dy = p2.y - p1.y
    return (dx * dx + dy * dy) ** 0.5


def normalize_score(score: int, max_score: int) -> float:
    """Normalize score to 0-1 range."""
    # BUG: DIV_ZERO - max_score could be 0
    return score / max_score


def get_spawn_point(spawn_points: list, index: int) -> Position:
    """Get spawn point by index."""
    # BUG: BOUNDS
    point = spawn_points[index]
    return Position(point[0], point[1])


def safe_move_player(player: Player, direction: int):
    """Safely move player, handling None position."""
    if player.position is None:
        return  # Safe: no-op for dead players
    
    if direction == 0:
        player.position.y -= 1
    elif direction == 1:
        player.position.x += 1
    elif direction == 2:
        player.position.y += 1
    elif direction == 3:
        player.position.x -= 1
