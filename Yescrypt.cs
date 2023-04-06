public class Yescrypt
        {
            private static readonly int ROUNDS = 10;
            private static readonly int BLOCK_SIZE = 256;
            private static readonly int OUTPUT_SIZE = 32;

            public static byte[] Hash(byte[] input)
            {
                byte[] salt = new byte[BLOCK_SIZE];
                byte[] password = input;
                byte[] output = new byte[OUTPUT_SIZE];

                // Inicializa o salt com o valor 0x00
                for (int i = 0; i < salt.Length; i++)
                {
                    salt[i] = 0x00;
                }

                // Executa as iterações de hash
                for (int i = 0; i < ROUNDS; i++)
                {
                    byte[] roundInput = Combine(salt, password);
                    Sha256Digest sha256 = new Sha256Digest();
                    sha256.BlockUpdate(roundInput, 0, roundInput.Length);
                    sha256.DoFinal(output, 0);
                    sha256.Reset();

                    Pbkdf2(p => sha256.BlockUpdate(p, 0, p.Length), output, salt, ROUNDS, BLOCK_SIZE, output.Length);
                    Pbkdf2(p => sha256.BlockUpdate(p, 0, p.Length), output, password, 1, OUTPUT_SIZE, output.Length);
                }

                return output;
            }

            private static void Pbkdf2(Action<byte[]> update, byte[] password, byte[] salt, int iterations,
                int blockSize,
                int outputSize)
            {
                int blockCount = (int)Math.Ceiling((double)outputSize / blockSize);
                byte[] output = new byte[blockCount * blockSize];
                byte[] block = new byte[blockSize];
                byte[] temp = new byte[blockSize + 4];
                int offset = 0;

                for (int i = 1; i <= blockCount; i++)
                {
                    // Gera o bloco
                    for (int j = 0; j < salt.Length; j++)
                    {
                        temp[j] = salt[j];
                    }

                    temp[blockSize + 0] = (byte)((i >> 24) & 0xFF);
                    temp[blockSize + 1] = (byte)((i >> 16) & 0xFF);
                    temp[blockSize + 2] = (byte)((i >> 8) & 0xFF);
                    temp[blockSize + 3] = (byte)((i >> 0) & 0xFF);

                    HmacSha256Digest hmac = new HmacSha256Digest();
                    hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(password));
                    hmac.BlockUpdate(temp, 0, temp.Length);
                    hmac.DoFinal(block, 0);
                    hmac.Reset();

                    for (int j = 1; j < iterations; j++)
                    {
                        hmac.BlockUpdate(block, 0, block.Length);
                        hmac.DoFinal(block, 0);
                        hmac.Reset();

                        for (int k = 0; k < blockSize; k++)
                        {
                            output[offset + k] ^= block[k];
                        }
                    }

                    offset += blockSize;
                }

                update(output);
            }

            private static byte[] Combine(byte[] a, byte[] b)
            {
                byte[] result = new byte[a.Length + b.Length];
                Array.Copy(a, result, a.Length);
                Array.Copy(b, 0, result, a.Length, b.Length);
                return result;
            }
        }

        public class HmacSha256Digest
        {
            private readonly HMac hmac;

            public HmacSha256Digest()
            {
                hmac = new HMac(new Sha256Digest());
            }

            public void Init(KeyParameter key)
            {
                hmac.Init(key);
            }

            public void BlockUpdate(byte[] input, int inOff, int len)
            {
                hmac.BlockUpdate(input, inOff, len);
            }

            public void DoFinal(byte[] output, int outOff)
            {
                hmac.DoFinal(output, outOff);
            }

            public void Reset()
            {
                hmac.Reset();
            }
        }
