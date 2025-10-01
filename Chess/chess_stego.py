# chess_stego.py loss-less
from time import time
from math import log2
import chess
import chess.pgn

# Placeholder for util.py functions
def to_binary_string(number: int, length: int) -> str:
    return format(number, f'0{length}b')

def get_pgn_games(pgn_string: str):
    """Parse PGN string into a list of chess.pgn.Game objects."""
    import io
    games = []
    pgn_io = io.StringIO(pgn_string)
    while True:
        game = chess.pgn.read_game(pgn_io)
        if game is None:
            break
        games.append(game)
    return games

def encode(file_path: str):
    start_time = time()
    with open(file_path, "rb") as f:
        file_bytes = list(f.read())
        file_bits_count = len(file_bytes) * 8
        if file_bits_count == 0:
            print("Error: Input file is empty.")
            return ""
    print(f"Input file: {file_bits_count} bits ({len(file_bytes)} bytes)")
    
    output_pgns = []
    file_bit_index = 0
    chess_board = chess.Board()
    print(f"Initial board FEN: {chess_board.fen()}")
    
    while True:
        legal_moves = list(chess_board.legal_moves)
        num_legal = len(legal_moves)
        print(f"Legal moves count: {num_legal}")
        if num_legal == 0:
            print("No legal moves, saving game.")
            game = chess.pgn.Game.from_board(chess_board)
            output_pgns.append(str(game))
            chess_board.reset()
            print(f"Board reset, move stack: {len(chess_board.move_stack)}")
            break
        
        max_binary_length = min(int(log2(num_legal)), file_bits_count - file_bit_index)
        print(f"Max binary length: {max_binary_length}, File bit index: {file_bit_index}/{file_bits_count}")
        if max_binary_length <= 0:
            print("Max binary length <= 0, breaking.")
            break
        
        legal_moves.sort(key=lambda move: move.uci())
        closest_byte_index = file_bit_index // 8
        remaining_bytes = file_bytes[closest_byte_index:]
        file_chunk_pool = "".join([to_binary_string(byte, 8) for byte in remaining_bytes[:2]])

        lm = [move.uci() for move in legal_moves]
        print(f"legal move list: {lm}")
        
        selected_move = None
        current_binary_length = max_binary_length
        while current_binary_length > 0 and selected_move is None:
            next_file_chunk = file_chunk_pool[file_bit_index % 8 : file_bit_index % 8 + current_binary_length]
            print(f"Trying file chunk: {next_file_chunk} ({current_binary_length} bits)")
            for index, legal_move in enumerate(legal_moves):
                move_binary = to_binary_string(index, current_binary_length)
                if move_binary == next_file_chunk:
                    selected_move = legal_move
                    print(f"Match found for chunk {next_file_chunk}, move: {selected_move.uci()}")
                    break
            if selected_move is None:
                print(f"No match for {next_file_chunk}, reducing to {current_binary_length - 1} bits")
                current_binary_length -= 1
        
        if selected_move is None:
            print("No match even with 1 bit, selecting first move to continue game.")
            selected_move = legal_moves[0]
            current_binary_length = 0  # No bits encoded, move chosen to progress game
        
        chess_board.push(selected_move)
        file_bit_index += current_binary_length
        print(f"Selected move: {selected_move.uci()}, Bits encoded: {current_binary_length}, New file bit index: {file_bit_index}/{file_bits_count}")
        
        eof_reached = file_bit_index >= file_bits_count
        if chess_board.is_game_over() or eof_reached:
            print(f"Game over: {chess_board.is_game_over()}, EOF reached: {eof_reached}")
            game = chess.pgn.Game.from_board(chess_board)
            output_pgns.append(str(game))
            chess_board.reset()
            print(f"Game saved, PGNs so far: {len(output_pgns)}, Move stack: {len(chess_board.move_stack)}")
            if eof_reached:
                print("All bits encoded, breaking.")
                break
    
    # Save final game if any moves were made
    if chess_board.move_stack:
        print("Saving final partial game.")
        game = chess.pgn.Game.from_board(chess_board)
        output_pgns.append(str(game))
    
    duration = round(time() - start_time, 3)
    print(f"Encoded {file_bit_index} bits into {len(output_pgns)} PGN(s) in {duration}s.")
    return "\n\n".join(output_pgns)

def decode(pgn_string: str, output_file_path: str):
    start_time = time()
    games = get_pgn_games(pgn_string)
    total_bits = 0
    reconstructed_bits = ""
    
    for game in games:
        board = chess.Board()
        for move in game.mainline_moves():
            legal_moves = list(board.legal_moves)
            legal_moves.sort(key=lambda m: m.uci())
            move_index = legal_moves.index(move)
            num_legal = len(legal_moves)
            bits_per_move = int(log2(num_legal))
            move_binary = to_binary_string(move_index, bits_per_move)
            reconstructed_bits += move_binary
            total_bits += bits_per_move
            board.push(move)
    
    # Convert binary string back to bytes (trim leading zeros if needed)
    byte_length = len(reconstructed_bits) // 8
    reconstructed_bytes = bytes(int(reconstructed_bits[i:i+8], 2) for i in range(0, byte_length*8, 8))
    
    with open(output_file_path, "wb") as f:
        f.write(reconstructed_bytes)
    
    duration = round(time() - start_time, 3)
    print(f"Decoded {total_bits} bits to {output_file_path} in {duration}s.")

# Demo runners
if __name__ == "__main__":
    action = input("Encode (e) or Decode (d)? ")
    if action.lower() == 'e':
        file_path = input("Input file: ")
        out_pgn = input("Output PGN file: ") or "output.pgn"
        pgn_result = encode(file_path)
        if not pgn_result:
            print("No PGN data generated.")
        else:
            try:
                with open(out_pgn, "w") as f:
                    f.write(pgn_result)
                print("PGN saved!")
            except Exception as e:
                print(f"Error writing to {out_pgn}: {e}")
    elif action.lower() == 'd':
        pgn_path = input("Input PGN file: ")
        try:
            with open(pgn_path, "r") as f:
                pgn_str = f.read()
        except Exception as e:
            print(f"Error reading {pgn_path}: {e}")
            exit(1)
        out_file = input("Output file: ") or "decoded.bin"
        try:
            decode(pgn_str, out_file)
            print("Decoded!")
        except Exception as e:
            print(f"Error decoding to {out_file}: {e}")
