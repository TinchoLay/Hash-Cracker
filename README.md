# Hash Cracker

A command-line tool that takes a hash and a wordlist, and tries to find which word produced that hash — using as many CPU cores as your machine has. Companion project to [Hash-Identifier](https://github.com/TinchoLay/Hash-Identifier): this tool imports it directly to figure out what kind of hash it's looking at before deciding how to attack it.

Built from scratch as a learning project, using [CarterPerez-dev's hash-cracker](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/hash-cracker) as the starting idea, not as a template to copy.

**[English](#english) | [Español](#español)**

---

## English

### What does "cracking a hash" actually mean?

A hash is a one-way fingerprint — you can turn a password into its hash easily, but there's no formula to turn the hash back into the password. So how does anyone ever recover a password from a hash? They don't reverse it. They *guess*, over and over: take a word, hash it, check if it matches. Try "password123", doesn't match. Try "letmein", doesn't match. Try "hello", matches — found it.

That's all "cracking" is: brute-force guessing, sped up by trying thousands or millions of guesses per second instead of by hand. A dictionary attack narrows the guessing to words people actually use — real passwords, not random strings — because most people's passwords aren't random at all.

### Why this exists

[Hash-Identifier](https://github.com/TinchoLay/Hash-Identifier), the companion project, answers "what algorithm produced this hash?" This project answers the next question: "given that algorithm, can I recover the original password from a wordlist?" They're separate tools on purpose — identifying is fast and diagnostic, cracking is computationally heavy — but this one actually imports the other as a real dependency, so you never have to tell it the algorithm by hand. Point it at a hash, it figures out the rest.

### A responsible-use note

This tool is built for auditing your own systems, for CTFs, and for learning how password security actually works — the same reason security teams run cracking tools against their own password databases to find weak ones before an attacker does. Only run it against hashes you own or have explicit permission to test. Using it against systems you don't have authorization for is illegal in most places, full stop.

### What it does

Point `crack` at a hash. It asks Hash-Identifier what the hash probably is, then either:

- **Attacks it** — for real password hashes (MD5, SHA-1, SHA-256, NTLM, bcrypt, Argon2, and the three Unix crypt variants), it tries every word in a wordlist, spread across all your CPU cores, until one matches or the list runs out.
- **Reverses it instantly** — Cisco Type 7 isn't a real hash, it's a reversible cipher. No guessing needed; the tool just undoes it.
- **Attacks the signing key** — for a JWT, "cracking" means finding the secret key the server used to sign it, not a password. Same underlying technique (try candidates, check for a match), aimed at a different target.

### Seeing it in action

```
$ hashcrack crack 5d41402abc4b2a76b9719d911017c592
Algoritmo detectado: MD5 (confianza: medium, vía hashid)
Probando contra 99 candidatos de wordlists/sample.txt...
¡Encontrado! hello
33 intentos en 0.59s (56 hashes/seg)
```

```
$ hashcrack crack 094F471A1A0A
Algoritmo detectado: Cisco IOS Type 7 (confianza: low, vía hashid)
Revertido directamente (sin búsqueda): cisco
```

(Output text is in Spanish — same as its companion project, kept consistent on purpose. Everything underneath, the code and the logic, reads the same regardless of language.)

That 56 hashes/second in the first example looks slow — it is, but only because the sample wordlist has 99 words in it. Spinning up several processes has a fixed startup cost, and with only 99 words to check, that startup cost dominates the whole run. Point it at a wordlist with a few hundred thousand words instead, and that same fixed cost becomes irrelevant next to the actual work — the real throughput is much higher.

### Installing it

You'll need Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/TinchoLay/Hash-Cracker.git
cd Hash-Cracker
uv sync
```

That last step also pulls in [Hash-Identifier](https://github.com/TinchoLay/Hash-Identifier) automatically, straight from its GitHub repo — it's declared as a real dependency, not copy-pasted code.

### Using it

```bash
# Auto-detect and attack
uv run hashcrack crack 5d41402abc4b2a76b9719d911017c592

# Use your own wordlist instead of the small sample included here
uv run hashcrack crack 5d41402abc4b2a76b9719d911017c592 --wordlist rockyou.txt

# A raw hash that was salted by hand before hashing (you need to know or guess the salt)
uv run hashcrack crack <hash> --salt mysalt --salt-position prepend

# Skip auto-detection if it guessed wrong or was ambiguous
uv run hashcrack crack <hash> --algorithm SHA-256
```

**The same Windows/PowerShell gotcha from Hash-Identifier applies here too:** bcrypt, Argon2, and Unix crypt hashes all contain `$` characters. In PowerShell, double quotes will silently mangle them (PowerShell tries to interpolate `$` as a variable). Use single quotes:

```powershell
uv run hashcrack crack '$2b$04$XRr.uHBOZgictPvLpVdLWOILmOje3Wbn3u6uE/CIYVGzO/U7SCW16'
```

### How it's built

Two small interfaces sit under everything: `Attack` (try a candidate, compute something comparable to the target) and `Reverser` (no guessing — just a formula that undoes the encoding directly, used only for Cisco Type 7). Every real hash algorithm is its own class implementing `Attack`, following the same one-format-one-class philosophy as the companion identifier project.

The guessing itself runs on `multiprocessing`, not `threading` — Python's GIL prevents threads from doing CPU-heavy work in parallel, so real processes are the only way to actually use more than one core for something like hashing. One tricky bit worth mentioning if it comes up in an interview: `multiprocessing.Pool` reuses a fixed set of worker processes and sends them tasks through a queue — and synchronization primitives like `Event` can't be sent through that queue, only passed once at pool creation. First version of the engine got this wrong and threw a `RuntimeError` about "objects should only be shared through inheritance"; the fix was passing the shared `Event` and counter through the pool's `initializer` instead of as part of each task.

Algorithms that expose a `verify(hash, password) -> bool` API instead of a "recompute the hash" function (Argon2, the Unix crypt variants) get adapted to the same `Attack` interface: on success they return the target hash itself so the equality check in the engine passes; on failure, a sentinel value that can never match anything real.

### Running the tests

```bash
uv run pytest -v
```

41 tests as of this writing.

### Credit

Conceptually inspired by [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects) — specifically the `beginner/hash-cracker` learning module. Built with a different architecture (Attack/Reverser split, multiprocessing from the start, real integration with a sibling project) and no reused code.

### License

MIT — see [LICENSE](LICENSE).

---

## Español

### ¿Qué significa "crackear" un hash?

Un hash es una huella de un solo sentido — podés convertir una contraseña en su hash fácilmente, pero no existe una fórmula para volver del hash a la contraseña. Entonces, ¿cómo se recupera una contraseña a partir de un hash? No se revierte. Se **adivina**, una y otra vez: agarrás una palabra, la hasheás, fijate si coincide. Probás "password123", no coincide. Probás "letmein", no coincide. Probás "hello", coincide — la encontraste.

Eso es "crackear": adivinar por fuerza bruta, acelerado probando miles o millones de intentos por segundo en vez de a mano. Un ataque de diccionario acota la adivinanza a palabras que la gente realmente usa — contraseñas reales, no strings al azar — porque la mayoría de las contraseñas de la gente no son para nada aleatorias.

### Por qué existe este proyecto

[Hash-Identifier](https://github.com/TinchoLay/Hash-Identifier), el proyecto hermano, responde "¿qué algoritmo generó este hash?". Este proyecto responde la pregunta siguiente: "sabiendo ese algoritmo, ¿puedo recuperar la contraseña original a partir de un diccionario?". Son herramientas separadas a propósito — identificar es rápido y diagnóstico, crackear es pesado computacionalmente — pero esta importa a la otra como una dependencia real, así que nunca hace falta indicarle el algoritmo a mano. Le apuntás a un hash, y el resto lo resuelve solo.

### Una nota sobre uso responsable

Esta herramienta está pensada para auditar tus propios sistemas, para CTFs, y para aprender cómo funciona de verdad la seguridad de contraseñas — la misma razón por la que los equipos de seguridad corren herramientas de cracking contra sus propias bases de contraseñas, para encontrar las débiles antes que un atacante. Usala únicamente contra hashes que sean tuyos o para los que tengas permiso explícito de probar. Usarla contra sistemas para los que no tenés autorización es ilegal en la mayoría de los lugares, sin vueltas.

### Qué hace

Le apuntás `crack` a un hash. Le pregunta a Hash-Identifier qué es probablemente, y después:

- **Lo ataca** — para hashes de contraseña reales (MD5, SHA-1, SHA-256, NTLM, bcrypt, Argon2, y las tres variantes de crypt de Unix), prueba cada palabra de un diccionario, repartido entre todos tus núcleos de CPU, hasta que una coincide o se agota la lista.
- **Lo revierte al instante** — Cisco Type 7 no es un hash real, es un cifrado reversible. No hace falta adivinar nada; la herramienta simplemente lo deshace.
- **Ataca la clave de firma** — en un JWT, "crackear" significa encontrar la clave secreta que el servidor usó para firmarlo, no una contraseña. Misma técnica de fondo (probar candidatos, comparar), apuntada a otro objetivo.

### Viéndolo en acción

```
$ hashcrack crack 5d41402abc4b2a76b9719d911017c592
Algoritmo detectado: MD5 (confianza: medium, vía hashid)
Probando contra 99 candidatos de wordlists/sample.txt...
¡Encontrado! hello
33 intentos en 0.59s (56 hashes/seg)
```

```
$ hashcrack crack 094F471A1A0A
Algoritmo detectado: Cisco IOS Type 7 (confianza: low, vía hashid)
Revertido directamente (sin búsqueda): cisco
```

Ese "56 hashes/seg" del primer ejemplo se ve lento — y lo es, pero solo porque el wordlist de muestra tiene 99 palabras. Levantar varios procesos tiene un costo fijo de arranque, y con solo 99 palabras para revisar, ese costo domina toda la corrida. Apuntá a un diccionario con unos cientos de miles de palabras y ese mismo costo fijo se vuelve irrelevante al lado del trabajo real — el rendimiento de crucero es mucho más alto.

### Instalación

Necesitás Python 3.11+ y [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/TinchoLay/Hash-Cracker.git
cd Hash-Cracker
uv sync
```

Ese último paso también trae [Hash-Identifier](https://github.com/TinchoLay/Hash-Identifier) automáticamente, directo desde su repo de GitHub — está declarado como una dependencia real, no es código copiado y pegado.

### Uso

```bash
# Autodetecta y ataca
uv run hashcrack crack 5d41402abc4b2a76b9719d911017c592

# Usar tu propio wordlist en vez del chico incluido acá
uv run hashcrack crack 5d41402abc4b2a76b9719d911017c592 --wordlist rockyou.txt

# Un hash crudo que fue salado a mano antes de calcularse (necesitás saber o sospechar la sal)
uv run hashcrack crack <hash> --salt misal --salt-position prepend

# Saltear la autodetección si adivinó mal o fue ambigua
uv run hashcrack crack <hash> --algorithm SHA-256
```

**El mismo detalle de Windows/PowerShell de Hash-Identifier aplica acá también:** los hashes bcrypt, Argon2 y crypt de Unix contienen caracteres `$`. En PowerShell, las comillas dobles los van a arruinar en silencio (PowerShell intenta interpolar el `$` como si fuera una variable). Usá comillas simples:

```powershell
uv run hashcrack crack '$2b$04$XRr.uHBOZgictPvLpVdLWOILmOje3Wbn3u6uE/CIYVGzO/U7SCW16'
```

### Cómo está construido

Dos interfaces chicas sostienen todo: `Attack` (probar un candidato, calcular algo comparable contra el objetivo) y `Reverser` (sin adivinar — solo una fórmula que deshace la codificación directamente, usada únicamente para Cisco Type 7). Cada algoritmo de hash real es su propia clase que implementa `Attack`, siguiendo la misma filosofía de "un formato, una clase" del proyecto identifier hermano.

La adivinanza en sí corre sobre `multiprocessing`, no `threading` — el GIL de Python impide que los hilos hagan trabajo de CPU en paralelo de verdad, así que procesos reales son la única forma de aprovechar más de un núcleo para algo como calcular hashes. Un detalle complicado que vale la pena mencionar si sale en una entrevista: `multiprocessing.Pool` reusa un grupo fijo de procesos trabajadores y les manda tareas por una cola — y los objetos de sincronización como `Event` no se pueden mandar por esa cola, solo pasarse una vez al crear el pool. La primera versión del motor no tuvo esto en cuenta y tiró un `RuntimeError` sobre "objetos que solo se pueden compartir por herencia"; la solución fue pasar el `Event` y el contador compartidos a través del `initializer` del pool, en vez de como parte de cada tarea.

Los algoritmos que exponen una API de `verify(hash, password) -> bool` en vez de una función de "recalcular el hash" (Argon2, las variantes de crypt de Unix) se adaptan a la misma interfaz `Attack`: si coincide, devuelven el propio hash objetivo para que la comparación del motor dé verdadero; si no, un valor centinela que nunca va a coincidir con nada real.

### Correr los tests

```bash
uv run pytest -v
```

41 tests al momento de escribir esto.

### Crédito

Inspirado conceptualmente en [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects) — específicamente el módulo educativo `beginner/hash-cracker`. Construido con una arquitectura distinta (separación Attack/Reverser, multiprocessing desde el principio, integración real con un proyecto hermano) y sin código reusado.

### Licencia

MIT — ver [LICENSE](LICENSE).
