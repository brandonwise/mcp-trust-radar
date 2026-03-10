from mcp_trust_radar.cli import build_parser


def test_parser_score_command():
    parser = build_parser()
    args = parser.parse_args(["score", "--input", "servers.json"])
    assert args.command == "score"
    assert args.input == "servers.json"
