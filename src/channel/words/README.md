# Verification words

The three lists of 2,048 words a channel verification reads aloud
(`src/channel/verify.rs`): `english.txt`, `french.txt` and `japanese.txt`,
copied byte for byte from BIP 39, the word lists most wallets in the world
use, chosen so that no two words of a list are easily confused.

Source: <https://github.com/bitcoin/bips/tree/master/bip-0039>, commit
`5aadddb511a5dcfe4599531bd8ae5e5b96d0f793` (26 October 2026).

| File | SHA-256 |
|---|---|
| `english.txt` | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| `french.txt` | `ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59` |
| `japanese.txt` | `2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd` |

A test checks each hash, so that a list can never drift: the same index must
read as the same word on both screens of a verification, whatever version
either side runs.

The lists are published under the MIT License by the authors of BIP 39:
Marek Palatinus, Pavol Rusnak, Aaron Voisine and Sean Bowe.

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
