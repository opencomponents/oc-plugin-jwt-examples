namespace jwt_example
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using Jose;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Security;

    class Program
    {
        static void Main(string[] args)
        {
            using (RSACryptoServiceProvider rsa = GetRSACryptoServiceProvider("private-key-encrypted.pem", "passphrase"))
            {
                var dataToSign = new Dictionary<string, object>
                {
                    {"sub", "1234567890"},
                    {"name", "John Doe"},
                    {"admin", true}
                };

                var extraHeaders = new Dictionary<string, object>
                {
                    {"typ", "JWT"},
                    {"kid", "key-id-1"}
                };
                var token = JWT.Encode(dataToSign, rsa, JwsAlgorithm.RS256, extraHeaders);
                Console.WriteLine(token);
            }
        }

        private static RSACryptoServiceProvider GetRSACryptoServiceProvider(string fileName, string passphrase)
        {
            var fileStream = File.OpenText(Path.Combine(AppContext.BaseDirectory, fileName));
            var pemReader = new PemReader(fileStream, new Password(passphrase));
            var keyPair = (AsymmetricCipherKeyPair) pemReader.ReadObject();
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters) keyPair.Private);
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParams);
            return rsa;
        }

        private class Password : IPasswordFinder
        {
            private readonly string _passphrase;

            public Password(string passphrase)
            {
                _passphrase = passphrase;
            }

            public char[] GetPassword()
            {
                return _passphrase.ToCharArray();
            }
        }
    }
}