# Cross-Organization Agent Delegated Authorization

This example demonstrates cross-organizational delegated authorization using a simulated agent economy. Organization A delegates specific authority (e.g., reading sales data) to its agent by issuing a signed token. The agent then uses this token to request an action from Organization B's service. Organization B's service validates the token's signature, scope, and expiration to ensure the agent has legitimate and limited authority, illustrating how trust is established and maintained between different entities in an agent economy.

## Language

`python`

## How to Run

1. Save the code as `main.py`.
2. Run from your terminal: `python main.py`

## Original Article

This example accompanies the Turkish article: [Çapraz Kurum Delege Yetkilendirmesi: Ajan Ekonomisinin En Büyük Güven Sorunu](https://fatihsoysal.com/blog/capraz-kurum-delege-yetkilendirmesi-ajan-ekonomisinin-en-buyuk-guven-sorunu/).

## License

MIT — see [LICENSE](LICENSE).
