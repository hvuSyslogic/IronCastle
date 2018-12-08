using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.text;

namespace org.bouncycastle.pqc.crypto.xmss
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// XMSS^MT.
	/// </summary>
	public sealed class XMSSMT
	{

		private XMSSMTParameters @params;
		private XMSSParameters xmssParams;
		private SecureRandom prng;
		private XMSSMTPrivateKeyParameters privateKey;
		private XMSSMTPublicKeyParameters publicKey;

		/// <summary>
		/// XMSSMT constructor...
		/// </summary>
		/// <param name="params"> XMSSMTParameters. </param>
		public XMSSMT(XMSSMTParameters @params, SecureRandom prng) : base()
		{
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			this.@params = @params;
			xmssParams = @params.getXMSSParameters();
			this.prng = prng;

			privateKey = (new XMSSMTPrivateKeyParameters.Builder(@params)).build();
			publicKey = (new XMSSMTPublicKeyParameters.Builder(@params)).build();
		}

		/// <summary>
		/// Generate a new XMSSMT private key / public key pair.
		/// </summary>
		public void generateKeys()
		{
			XMSSMTKeyPairGenerator kpGen = new XMSSMTKeyPairGenerator();

			kpGen.init(new XMSSMTKeyGenerationParameters(getParams(), prng));

			AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

			privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
			publicKey = (XMSSMTPublicKeyParameters)kp.getPublic();

			importState(privateKey, publicKey);
		}

		private void importState(XMSSMTPrivateKeyParameters privateKey, XMSSMTPublicKeyParameters publicKey)
		{
			/* import to xmss */
			xmssParams.getWOTSPlus().importKeys(new byte[@params.getDigestSize()], this.privateKey.getPublicSeed());

			this.privateKey = privateKey;
			this.publicKey = publicKey;
		}

		/// <summary>
		/// Import XMSSMT private key / public key pair.
		/// </summary>
		/// <param name="privateKey"> XMSSMT private key. </param>
		/// <param name="publicKey">  XMSSMT public key. </param>
		public void importState(byte[] privateKey, byte[] publicKey)
		{
			if (privateKey == null)
			{
				throw new NullPointerException("privateKey == null");
			}
			if (publicKey == null)
			{
				throw new NullPointerException("publicKey == null");
			}
			XMSSMTPrivateKeyParameters xmssMTPrivateKey = (new XMSSMTPrivateKeyParameters.Builder(@params)).withPrivateKey(privateKey, xmssParams).build();
			XMSSMTPublicKeyParameters xmssMTPublicKey = (new XMSSMTPublicKeyParameters.Builder(@params)).withPublicKey(publicKey).build();
			if (!Arrays.areEqual(xmssMTPrivateKey.getRoot(), xmssMTPublicKey.getRoot()))
			{
				throw new IllegalStateException("root of private key and public key do not match");
			}
			if (!Arrays.areEqual(xmssMTPrivateKey.getPublicSeed(), xmssMTPublicKey.getPublicSeed()))
			{
				throw new IllegalStateException("public seed of private key and public key do not match");
			}

			/* import to xmss */
			xmssParams.getWOTSPlus().importKeys(new byte[@params.getDigestSize()], xmssMTPrivateKey.getPublicSeed());

			this.privateKey = xmssMTPrivateKey;
			this.publicKey = xmssMTPublicKey;
		}

		/// <summary>
		/// Sign message.
		/// </summary>
		/// <param name="message"> Message to sign. </param>
		/// <returns> XMSSMT signature on digest of message. </returns>
		public byte[] sign(byte[] message)
		{
			if (message == null)
			{
				throw new NullPointerException("message == null");
			}

			XMSSMTSigner signer = new XMSSMTSigner();

			signer.init(true, privateKey);

			byte[] signature = signer.generateSignature(message);

			privateKey = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

			importState(privateKey, publicKey);

			return signature;
		}

		/// <summary>
		/// Verify an XMSSMT signature.
		/// </summary>
		/// <param name="message">   Message. </param>
		/// <param name="signature"> XMSSMT signature. </param>
		/// <param name="publicKey"> XMSSMT public key. </param>
		/// <returns> true if signature is valid false else. </returns>
		/// <exception cref="ParseException"> </exception>
		public bool verifySignature(byte[] message, byte[] signature, byte[] publicKey)
		{
			if (message == null)
			{
				throw new NullPointerException("message == null");
			}
			if (signature == null)
			{
				throw new NullPointerException("signature == null");
			}
			if (publicKey == null)
			{
				throw new NullPointerException("publicKey == null");
			}

			XMSSMTSigner signer = new XMSSMTSigner();

			signer.init(false, (new XMSSMTPublicKeyParameters.Builder(getParams())).withPublicKey(publicKey).build());

			return signer.verifySignature(message, signature);
		}

		/// <summary>
		/// Export XMSSMT private key.
		/// </summary>
		/// <returns> XMSSMT private key. </returns>
		public byte[] exportPrivateKey()
		{
			return privateKey.toByteArray();
		}

		/// <summary>
		/// Export XMSSMT public key.
		/// </summary>
		/// <returns> XMSSMT public key. </returns>
		public byte[] exportPublicKey()
		{
			return publicKey.toByteArray();
		}

		/// <summary>
		/// Getter XMSSMT params.
		/// </summary>
		/// <returns> XMSSMT params. </returns>
		public XMSSMTParameters getParams()
		{
			return @params;
		}


		/// <summary>
		/// Getter public seed.
		/// </summary>
		/// <returns> Public seed. </returns>
		public byte[] getPublicSeed()
		{
			return privateKey.getPublicSeed();
		}

		public XMSSParameters getXMSS()
		{
			return xmssParams;
		}
	}

}