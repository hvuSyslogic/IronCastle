using System;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{


	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using McElieceCipher = org.bouncycastle.pqc.crypto.mceliece.McElieceCipher;
	using McElieceKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceKeyParameters;
	using AsymmetricBlockCipher = org.bouncycastle.pqc.jcajce.provider.util.AsymmetricBlockCipher;

	public class McEliecePKCSCipherSpi : AsymmetricBlockCipher, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{
		private McElieceCipher cipher;

		public McEliecePKCSCipherSpi(McElieceCipher cipher)
		{
			this.cipher = cipher;
		}

		public override void initCipherEncrypt(Key key, AlgorithmParameterSpec @params, SecureRandom sr)
		{

			CipherParameters param;
			param = McElieceKeysToParams.generatePublicKeyParameter((PublicKey)key);

			param = new ParametersWithRandom(param, sr);
			cipher.init(true, param);
			this.maxPlainTextSize = cipher.maxPlainTextSize;
			this.cipherTextSize = cipher.cipherTextSize;
		}

		public override void initCipherDecrypt(Key key, AlgorithmParameterSpec @params)
		{
			CipherParameters param;
			param = McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)key);

			cipher.init(false, param);
			this.maxPlainTextSize = cipher.maxPlainTextSize;
			this.cipherTextSize = cipher.cipherTextSize;
		}

		public override byte[] messageEncrypt(byte[] input)
		{
			byte[] output = null;
			try
			{
				output = cipher.messageEncrypt(input);
			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}
			return output;
		}

		public override byte[] messageDecrypt(byte[] input)
		{
			byte[] output = null;
			try
			{
				output = cipher.messageDecrypt(input);
			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}
			return output;
		}

		public override string getName()
		{
			return "McEliecePKCS";
		}

		public override int getKeySize(Key key)
		{
			McElieceKeyParameters mcElieceKeyParameters;
			if (key is PublicKey)
			{
				mcElieceKeyParameters = (McElieceKeyParameters)McElieceKeysToParams.generatePublicKeyParameter((PublicKey)key);
			}
			else
			{
				mcElieceKeyParameters = (McElieceKeyParameters)McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)key);

			}


			return cipher.getKeySize(mcElieceKeyParameters);
		}

		public class McEliecePKCS : McEliecePKCSCipherSpi
		{
			public McEliecePKCS() : base(new McElieceCipher())
			{
			}
		}
	}

}