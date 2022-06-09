#!/usr/bin/env python
# coding: utf-8

# ## Pregunta 1
# Para esta pregunta vamos a definir tres funciones que implementan los conceptos vistos en clases con el objetivo de crear una función de hash resistente a colisiones. En esta implementacion para mensajes, cifrados y hashes se utilizara el tipo bytearray.

# ### Davies-Meyer
# 
# Esta es una funcion de compresion basada en el esquema davies_meyer. La propiedad más importante de esta construcción es que si el esquema criptografico que se esta utilizando es ideal, la compresion es resistente a colisiones.

# In[143]:


def davies_meyer(encrypt: callable, l_key: int, l_message: int) -> callable:
    def comp(message: bytearray) -> bytearray:
        mess = bytearray(message[:l_message])
        k = bytearray(message[l_message:l_message + l_key])
        H = encrypt(k, mess)
        new_message = bytearray([a ^ b for a, b in zip(mess, H)])
        return new_message
    return comp


# ### Padding
# 
# Esta función recibe un mensaje de largo arbitrario y hace dos cosas. Añade caracteres para que el largo del mensaje sea divisible en el tamaño de los bloques. También añade un bloque al final con el largo del mensaje original. En esta funcion de pad, el mensaje m es siempre prefijo de pad(m). Dados dos mensajes m1, m2, si tienen el mismo largo, el ultimo bloque de pad(m1) y pad(m2) es identico. Si tienen largo distinto, el ultimo bloque también tiene que ser distinto.

# In[144]:


def pad(message: bytearray, l_block: int) -> bytearray:
    new_message = message
    mes_length = bytearray(len(message).to_bytes(l_block, "big"))
    diff = len(message) % l_block
    if diff != 0:
        new_message += bytearray(int(1).to_bytes(1, "big"))
        for _ in range(1, l_block - diff):
            new_message += bytearray(int(0).to_bytes(1, "big"))

    new_message += mes_length
    return bytearray(new_message)


# ### Merkle-Damgard
# 
# Esta función implementa el esquema merkle_damgard para crea una función de hash resistente a colisiones. Para esto necesita un vector de inicializacion, una funcion de compresión y el largo del hash requerido. Esta funcion de hash recibe mensajes de largo arbitrario, utiliza la funcion de pad para normalizar su largo. Después utiliza la funcion de compresión para comprimir el mensaje original bloque por bloque hasta llegar a un texto final del largo requerido.
# 
# Para que esta función de hash creada sea resistente a colisiones, se necesita que la funcion de compresion sea criptograficamente segura. También requiere que la funcion de pad sea consistente, es decir, que para mensajes de largo igual, el ultimo bloque sea identico y que para el caso contrario, el ultimo bloque sea distinto y que el mensaje es prefijo del padding.

# In[145]:


def merkle_damgard(IV: bytearray, comp: callable, l_block: int) -> bytearray:
    def hash(message: bytearray) -> bytearray:
        new_mess = pad(message, l_block)
        H = IV
        blocks = len(new_mess) // l_block
        for i in range(blocks):
            block = new_mess[l_block * i: l_block * (i + 1)]
            H = comp(bytearray(H + block))
        return H
    return hash


# ### Funciones de encriptación de prueba
# 
# Para probar nuestras funciones utilizaremos el algoritmo de encriptacion AES128 que utiliza mensajes y llaves de 16 bits

# In[146]:


if __name__ == "__main__":
    pass
    #%pip install pycryptodome


# In[147]:


if __name__ == "__main__":
    from Crypto.Cipher import AES


# In[148]:


if __name__ == "__main__":
    def test_encrypt(key: bytearray, message: bytearray) -> bytearray:
        new_message = bytearray([(a+1) ^ (b+1) for a, b in zip(key, message)])
        return new_message

    def aes_128(key: bytearray, message: bytearray) -> bytearray:
        a = AES.new(key, AES.MODE_ECB)
        return bytearray(a.encrypt(message))


# In[149]:


if __name__ == "__main__":

    comp_test = davies_meyer(test_encrypt, 16, 16)
    comp_aes = davies_meyer(aes_128, 16, 16)
    hash = merkle_damgard(bytearray(b"1234567890123456"), comp_aes, 16)
    s1 = bytearray(b'Este es un mensaje de prueba para la tarea 2')
    s2 = bytearray(b'Este es un mensaje de Prueba para la tarea 2')
    s3 = bytearray(b'Un mensaje corto')
    s4 = bytearray(b'')

    h1 = hash(s1)
    h2 = hash(s2)
    h3 = hash(s3)
    h4 = hash(s4)

    expectedh1 = bytearray(b'\xe9\xe8\xac\x12\\\xf2\xc8\x16\xceOV\xc5Y.T\xea')
    expectedh2 = bytearray(b'\xb6\xfb\xc6a\x12\xae\x95\x1f\xda\xc5\x13\xde\x06|Q\x96')
    expectedh3 = bytearray(b'\xc5\xec\xcdd\xa4(R*\xf0L*QtL\xda\x81')
    expectedh4 = bytearray(b'p\xca \xd8\x9c\xeb\xe6\xb1\xce\xcf\x03\xb2\x9e\x93\x19\xbc')

    print(h1 == expectedh1, h1)
    print(h2 == expectedh2, h2)
    print(h3 == expectedh3, h3)
    print(h4 == expectedh4, h4)

