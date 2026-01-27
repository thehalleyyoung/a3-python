"""Test harness for game engine - triggers buggy functions."""


def test_get_player_oob():
    """Get player at bad index - triggers BOUNDS."""
    players = []
    player_id = 0
    # BUG: BOUNDS
    return players[player_id]


def test_update_none_position():
    """Update player with None position - triggers NULL_PTR."""
    class Position:
        x: int
        y: int
    
    class Player:
        position = None  # Dead player
    
    player = Player()
    # BUG: NULL_PTR
    if player.position.x < 0:
        player.position.x = 0


def test_calculate_average_score_empty():
    """Calculate average with no players - triggers DIV_ZERO."""
    players = []
    total = sum(0 for _ in players)  # 0
    # BUG: DIV_ZERO
    return total / len(players)


def test_get_leaderboard_oob():
    """Get leaderboard rank out of range - triggers BOUNDS."""
    players = [{"score": 10}]
    rank = 5
    sorted_players = sorted(players, key=lambda p: p["score"], reverse=True)
    # BUG: BOUNDS
    return sorted_players[rank]


def test_get_player_position_none():
    """Get position from dead player - triggers NULL_PTR."""
    class Player:
        position = None
    
    player = Player()
    # BUG: NULL_PTR
    return (player.position.x, player.position.y)


def test_get_player_from_list_oob():
    """Get player from empty list - triggers BOUNDS."""
    players = []
    index = 0
    # BUG: BOUNDS
    return players[index]


def test_calculate_health_percent_zero():
    """Calculate health with zero max - triggers DIV_ZERO."""
    health = 50
    max_health = 0
    # BUG: DIV_ZERO
    return (health / max_health) * 100


def test_move_player_none_position():
    """Move dead player - triggers NULL_PTR."""
    class Player:
        position = None
    
    player = Player()
    direction = 1
    # BUG: NULL_PTR
    player.position.x += 1


def test_check_collision_none():
    """Check collision with None positions - triggers NULL_PTR."""
    class P1:
        position = None
    class P2:
        class Pos:
            x = 0
            y = 0
        position = Pos()
    
    p1, p2 = P1(), P2()
    # BUG: NULL_PTR
    return p1.position.x == p2.position.x


def test_get_distance_none():
    """Get distance with None position - triggers NULL_PTR."""
    p1 = None
    class P2:
        x = 0
        y = 0
    p2 = P2()
    # BUG: NULL_PTR
    dx = p2.x - p1.x


def test_normalize_score_zero():
    """Normalize with zero max - triggers DIV_ZERO."""
    score = 100
    max_score = 0
    # BUG: DIV_ZERO
    return score / max_score


def test_get_spawn_point_oob():
    """Get spawn point at bad index - triggers BOUNDS."""
    spawn_points = []
    index = 0
    # BUG: BOUNDS
    return spawn_points[index]


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_average_score_empty()
    except ZeroDivisionError:
        pass
