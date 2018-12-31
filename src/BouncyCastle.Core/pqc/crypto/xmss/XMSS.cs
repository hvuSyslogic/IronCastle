using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.text;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

		
	/// <summary>
	/// XMSS.
	/// </summary>
	public class XMSS
	{

		/// <summary>
		/// XMSS parameters.
		/// </summary>
		private readonly XMSSParameters @params;
		/// <summary>
		/// WOTS+ instance.
		/// </summary>
		private WOTSPlus wotsPlus;
		/// <summary>
		/// PRNG.
		/// </summary>
		private SecureRandom prng;

		/// <summary>
		/// XMSS private key.
		/// </summary>
		private XMSSPrivateKeyParameters privateKey;
		/// <summary>
		/// XMSS public key.
		/// </summary>
		private XMSSPublicKeyParameters publicKey;

		/// <summary>
		/// XMSS constructor...
		/// </summary>
		/// <param name="params"> XMSSParameters. </param>
		public XMSS(XMSSParameters @params, SecureRandom prng) : base()
		{
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			this.@params = @params;
			wotsPlus = @params.getWOTSPlus();
			this.prng = prng;
		}

	//    public void generateKeys()
	//    {
	//        /* generate private key */
	//        privateKey = generatePrivateKey(params, prng);
	//        XMSSNode root = privateKey.getBDSState().initialize(privateKey, (OTSHashAddress)new OTSHashAddress.Builder().build());
	//
	//        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
	//            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
	//            .withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue())
	//            .withBDSState(privateKey.getBDSState()).build();
	//        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root.getValue())
	//            .withPublicSeed(getPublicSeed()).build();
	//
	//    }
	//
	//    /**
	//     * Generate an XMSS private key.
	//     *
	//     * @return XMSS private key.
	//     */
	//    private XMSSPrivateKeyParameters generatePrivateKey(XMSSParameters params, SecureRandom prng)
	//    {
	//        int n = params.getDigestSize();
	//        byte[] secretKeySeed = new byte[n];
	//        prng.nextBytes(secretKeySeed);
	//        byte[] secretKeyPRF = new byte[n];
	//        prng.nextBytes(secretKeyPRF);
	//        byte[] publicSeed = new byte[n];
	//        prng.nextBytes(publicSeed);
	//
	//        XMSS xmss = new XMSS(params, prng);
	//
	////        this.privateKey = xmss.privateKey;
	////        this.publicKey = xmss.publicKey;
	////        this.wotsPlus = xmss.wotsPlus;
	////        this.khf = xmss.khf;
	//
	//        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
	//            .withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
	//            .withBDSState(new BDS(xmss)).build();
	//
	//        return privateKey;
	//    }

		/// <summary>
		/// Generate a new XMSS private key / public key pair.
		/// </summary>
		public virtual void generateKeys()
		{
			XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();

			kpGen.init(new XMSSKeyGenerationParameters(getParams(), prng));

			AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

			privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();
			publicKey = (XMSSPublicKeyParameters)kp.getPublic();

			wotsPlus.importKeys(new byte[@params.getDigestSize()], this.privateKey.getPublicSeed());
		}

		public virtual void importState(XMSSPrivateKeyParameters privateKey, XMSSPublicKeyParameters publicKey)
		{
			if (!Arrays.areEqual(privateKey.getRoot(), publicKey.getRoot()))
			{
				throw new IllegalStateException("root of private key and public key do not match");
			}
			if (!Arrays.areEqual(privateKey.getPublicSeed(), publicKey.getPublicSeed()))
			{
				throw new IllegalStateException("public seed of private key and public key do not match");
			}
			/* import */
			this.privateKey = privateKey;
			this.publicKey = publicKey;

			wotsPlus.importKeys(new byte[@params.getDigestSize()], this.privateKey.getPublicSeed());
		}

		/// <summary>
		/// Import XMSS private key / public key pair.
		/// </summary>
		/// <param name="privateKey"> XMSS private key. </param>
		/// <param name="publicKey">  XMSS public key. </param>
		public virtual void importState(byte[] privateKey, byte[] publicKey)
		{
			if (privateKey == null)
			{
				throw new NullPointerException("privateKey == null");
			}
			if (publicKey == null)
			{
				throw new NullPointerException("publicKey == null");
			}
			/* import keys */
			XMSSPrivateKeyParameters tmpPrivateKey = (new XMSSPrivateKeyParameters.Builder(@params)).withPrivateKey(privateKey, this.getParams()).build();
			XMSSPublicKeyParameters tmpPublicKey = (new XMSSPublicKeyParameters.Builder(@params)).withPublicKey(publicKey).build();
			if (!Arrays.areEqual(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot()))
			{
				throw new IllegalStateException("root of private key and public key do not match");
			}
			if (!Arrays.areEqual(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed()))
			{
				throw new IllegalStateException("public seed of private key and public key do not match");
			}
			/* import */
			this.privateKey = tmpPrivateKey;
			this.publicKey = tmpPublicKey;
			wotsPlus.importKeys(new byte[@params.getDigestSize()], this.privateKey.getPublicSeed());
		}

		/// <summary>
		/// Sign message.
		/// </summary>
		/// <param name="message"> Message to sign. </param>
		/// <returns> XMSS signature on digest of message. </returns>
		public virtual byte[] sign(byte[] message)
		{
			if (message == null)
			{
				throw new NullPointerException("message == null");
			}
			XMSSSigner signer = new XMSSSigner();

			signer.init(true, privateKey);

			byte[] signature = signer.generateSignature(message);

			privateKey = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

			importState(privateKey, publicKey);

			return signature;
		}

		/// <summary>
		/// Verify an XMSS signature.
		/// </summary>
		/// <param name="message">   Message. </param>
		/// <param name="signature"> XMSS signature. </param>
		/// <param name="publicKey"> XMSS public key. </param>
		/// <returns> true if signature is valid false else. </returns>
		/// <exception cref="ParseException"> </exception>
		public virtual bool verifySignature(byte[] message, byte[] signature, byte[] publicKey)
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

			XMSSSigner signer = new XMSSSigner();

			signer.init(false, (new XMSSPublicKeyParameters.Builder(getParams())).withPublicKey(publicKey).build());

			return signer.verifySignature(message, signature);
		}

		/// <summary>
		/// Export XMSS private key.
		/// </summary>
		/// <returns> XMSS private key. </returns>
		public virtual byte[] exportPrivateKey()
		{
			return privateKey.toByteArray();
		}

		/// <summary>
		/// Export XMSS public key.
		/// </summary>
		/// <returns> XMSS public key. </returns>
		public virtual byte[] exportPublicKey()
		{
			return publicKey.toByteArray();
		}

		/// <summary>
		/// Generate a WOTS+ signature on a message without the corresponding
		/// authentication path
		/// </summary>
		/// <param name="messageDigest">  Message digest of length n. </param>
		/// <param name="otsHashAddress"> OTS hash address. </param>
		/// <returns> XMSS signature. </returns>
		public virtual WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress)
		{
			if (messageDigest.Length != @params.getDigestSize())
			{
				throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
			}
			if (otsHashAddress == null)
			{
				throw new NullPointerException("otsHashAddress == null");
			}
			/* (re)initialize WOTS+ instance */
			wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(privateKey.getSecretKeySeed(), otsHashAddress), getPublicSeed());
			/* create WOTS+ signature */
			return wotsPlus.sign(messageDigest, otsHashAddress);
		}

		/// <summary>
		/// Getter XMSS params.
		/// </summary>
		/// <returns> XMSS params. </returns>
		public virtual XMSSParameters getParams()
		{
			return @params;
		}

		/// <summary>
		/// Getter WOTS+.
		/// </summary>
		/// <returns> WOTS+ instance. </returns>
		public virtual WOTSPlus getWOTSPlus()
		{
			return wotsPlus;
		}

		/// <summary>
		/// Getter XMSS root.
		/// </summary>
		/// <returns> Root of binary tree. </returns>
		public virtual byte[] getRoot()
		{
			return privateKey.getRoot();
		}

		public virtual void setRoot(byte[] root)
		{
			privateKey = (new XMSSPrivateKeyParameters.Builder(@params)).withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(getPublicSeed()).withRoot(root).withBDSState(privateKey.getBDSState()).build();
			publicKey = (new XMSSPublicKeyParameters.Builder(@params)).withRoot(root).withPublicSeed(getPublicSeed()).build();
		}

		/// <summary>
		/// Getter XMSS index.
		/// </summary>
		/// <returns> Index. </returns>
		public virtual int getIndex()
		{
			return privateKey.getIndex();
		}

		public virtual void setIndex(int index)
		{
			privateKey = (new XMSSPrivateKeyParameters.Builder(@params)).withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot()).withBDSState(privateKey.getBDSState()).build();
		}

		/// <summary>
		/// Getter XMSS public seed.
		/// </summary>
		/// <returns> Public seed. </returns>
		public virtual byte[] getPublicSeed()
		{
			return privateKey.getPublicSeed();
		}

		public virtual void setPublicSeed(byte[] publicSeed)
		{
			privateKey = (new XMSSPrivateKeyParameters.Builder(@params)).withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(publicSeed).withRoot(getRoot()).withBDSState(privateKey.getBDSState()).build();
			publicKey = (new XMSSPublicKeyParameters.Builder(@params)).withRoot(getRoot()).withPublicSeed(publicSeed).build();

			wotsPlus.importKeys(new byte[@params.getDigestSize()], publicSeed);
		}

		public virtual XMSSPrivateKeyParameters getPrivateKey()
		{
			return privateKey;
		}
	}

}