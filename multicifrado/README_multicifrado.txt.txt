instalacion en Linux:

pip3 install cryptography


Arrancas el programa:
entrar en el directorio, abre una terminal ahí y introduce

python3 multicifrado.py

Eliges el algoritmo.
Eliges cifrar o descifrar.
introduces la contraseña que quieras
Introduces texto (letras, números y símbolos).

Obtienes el resultado.

Ejemplo

=== SISTEMA DE CIFRADO ===

1 - AES-256-GCM
2 - ChaCha20-Poly1305
3 - ...

Algoritmo: 1

1 - Cifrar
2 - Descifrar

Acción: 1

Contraseña: mi_clave_super_secreta

Texto: Hola mundo 123

Resultado:
M3hWmN4QY0h3...

Luego copias ese bloque cifrado, eliges "Descifrar",
 introduces la misma contraseña y 
recuperas el texto original. 
Esto permite cifrar cualquier cadena de texto 
(letras, números, espacios y símbolos) usando algoritmos.
Se puede cifrar un texto mas de una vez con diferentes algoritmos
para mas seguridad