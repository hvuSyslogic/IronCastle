using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.generators;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{

										
	/// <summary>
	/// Support class for constructing integrated encryption ciphers
	/// for doing basic message exchanges on top of key agreement ciphers.
	/// Follows the description given in IEEE Std 1363a.
	/// </summary>
	public class IESEngine
	{
		internal BasicAgreement agree;
		internal DerivationFunction kdf;
		internal Mac mac;
		internal BufferedBlockCipher cipher;
		internal byte[] macBuf;

		internal bool forEncryption;
		internal CipherParameters privParam, pubParam;
		internal IESParameters param;

		internal byte[] V;
		private EphemeralKeyPairGenerator keyPairGenerator;
		private KeyParser keyParser;
		private byte[] IV;

		/// <summary>
		/// Set up for use with stream mode, where the key derivation function
		/// is used to provide a stream of bytes to xor with the message.
		/// </summary>
		/// <param name="agree"> the key agreement used as the basis for the encryption </param>
		/// <param name="kdf">   the key derivation function used for byte generation </param>
		/// <param name="mac">   the message authentication code generator for the message </param>
		public IESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac)
		{
			this.agree = agree;
			this.kdf = kdf;
			this.mac = mac;
			this.macBuf = new byte[mac.getMacSize()];
			this.cipher = null;
		}


		/// <summary>
		/// Set up for use in conjunction with a block cipher to handle the
		/// message. It is <b>strongly</b> recommended that the cipher is not in ECB mode.
		/// </summary>
		/// <param name="agree">  the key agreement used as the basis for the encryption </param>
		/// <param name="kdf">    the key derivation function used for byte generation </param>
		/// <param name="mac">    the message authentication code generator for the message </param>
		/// <param name="cipher"> the cipher to used for encrypting the message </param>
		public IESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac, BufferedBlockCipher cipher)
		{
			this.agree = agree;
			this.kdf = kdf;
			this.mac = mac;
			this.macBuf = new byte[mac.getMacSize()];
			this.cipher = cipher;
		}

		/// <summary>
		/// Initialise the encryptor.
		/// </summary>
		/// <param name="forEncryption"> whether or not this is encryption/decryption. </param>
		/// <param name="privParam">     our private key parameters </param>
		/// <param name="pubParam">      the recipient's/sender's public key parameters </param>
		/// <param name="params">        encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher. </param>
		public virtual void init(bool forEncryption, CipherParameters privParam, CipherParameters pubParam, CipherParameters @params)
		{
			this.forEncryption = forEncryption;
			this.privParam = privParam;
			this.pubParam = pubParam;
			this.V = new byte[0];

			extractParams(@params);
		}

		/// <summary>
		/// Initialise the decryptor.
		/// </summary>
		/// <param name="publicKey">      the recipient's/sender's public key parameters </param>
		/// <param name="params">         encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher. </param>
		/// <param name="ephemeralKeyPairGenerator">             the ephemeral key pair generator to use. </param>
		public virtual void init(AsymmetricKeyParameter publicKey, CipherParameters @params, EphemeralKeyPairGenerator ephemeralKeyPairGenerator)
		{
			this.forEncryption = true;
			this.pubParam = publicKey;
			this.keyPairGenerator = ephemeralKeyPairGenerator;

			extractParams(@params);
		}

		/// <summary>
		/// Initialise the encryptor.
		/// </summary>
		/// <param name="privateKey">      the recipient's private key. </param>
		/// <param name="params">          encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher. </param>
		/// <param name="publicKeyParser"> the parser for reading the ephemeral public key. </param>
		public virtual void init(AsymmetricKeyParameter privateKey, CipherParameters @params, KeyParser publicKeyParser)
		{
			this.forEncryption = false;
			this.privParam = privateKey;
			this.keyParser = publicKeyParser;

			extractParams(@params);
		}

		private void extractParams(CipherParameters @params)
		{
			if (@params is ParametersWithIV)
			{
				this.IV = ((ParametersWithIV)@params).getIV();
				this.param = (IESParameters)((ParametersWithIV)@params).getParameters();
			}
			else
			{
				this.IV = null;
				this.param = (IESParameters)@params;
			}
		}

		public virtual BufferedBlockCipher getCipher()
		{
			return cipher;
		}

		public virtual Mac getMac()
		{
			return mac;
		}

		private byte[] encryptBlock(byte[] @in, int inOff, int inLen)
		{
			byte[] C = null, K = null, K1 = null, K2 = null;
			int len;

			if (cipher == null)
			{
				// Streaming mode.
				K1 = new byte[inLen];
				K2 = new byte[param.getMacKeySize() / 8];
				K = new byte[K1.Length + K2.Length];

				kdf.generateBytes(K, 0, K.Length);

				if (V.Length != 0)
				{
					JavaSystem.arraycopy(K, 0, K2, 0, K2.Length);
					JavaSystem.arraycopy(K, K2.Length, K1, 0, K1.Length);
				}
				else
				{
					JavaSystem.arraycopy(K, 0, K1, 0, K1.Length);
					JavaSystem.arraycopy(K, inLen, K2, 0, K2.Length);
				}

				C = new byte[inLen];

				for (int i = 0; i != inLen; i++)
				{
					C[i] = (byte)(@in[inOff + i] ^ K1[i]);
				}
				len = inLen;
			}
			else
			{
				// Block cipher mode.
				K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
				K2 = new byte[param.getMacKeySize() / 8];
				K = new byte[K1.Length + K2.Length];

				kdf.generateBytes(K, 0, K.Length);
				JavaSystem.arraycopy(K, 0, K1, 0, K1.Length);
				JavaSystem.arraycopy(K, K1.Length, K2, 0, K2.Length);

				// If iv provided use it to initialise the cipher
				if (IV != null)
				{
					cipher.init(true, new ParametersWithIV(new KeyParameter(K1), IV));
				}
				else
				{
					cipher.init(true, new KeyParameter(K1));
				}

				C = new byte[cipher.getOutputSize(inLen)];
				len = cipher.processBytes(@in, inOff, inLen, C, 0);
				len += cipher.doFinal(C, len);
			}


			// Convert the length of the encoding vector into a byte array.
			byte[] P2 = param.getEncodingV();
			byte[] L2 = null;
			if (V.Length != 0)
			{
				L2 = getLengthTag(P2);
			}


			// Apply the MAC.
			byte[] T = new byte[mac.getMacSize()];

			mac.init(new KeyParameter(K2));
			mac.update(C, 0, C.Length);
			if (P2 != null)
			{
				mac.update(P2, 0, P2.Length);
			}
			if (V.Length != 0)
			{
				mac.update(L2, 0, L2.Length);
			}
			mac.doFinal(T, 0);


			// Output the triple (V,C,T).
			byte[] Output = new byte[V.Length + len + T.Length];
			JavaSystem.arraycopy(V, 0, Output, 0, V.Length);
			JavaSystem.arraycopy(C, 0, Output, V.Length, len);
			JavaSystem.arraycopy(T, 0, Output, V.Length + len, T.Length);
			return Output;
		}

		private byte[] decryptBlock(byte[] in_enc, int inOff, int inLen)
		{
			byte[] M, K, K1, K2;
			int len = 0;

			// Ensure that the length of the input is greater than the MAC in bytes
			if (inLen < V.Length + mac.getMacSize())
			{
				throw new InvalidCipherTextException("Length of input must be greater than the MAC and V combined");
			}

			// note order is important: set up keys, do simple encryptions, check mac, do final encryption.
			if (cipher == null)
			{
				// Streaming mode.
				K1 = new byte[inLen - V.Length - mac.getMacSize()];
				K2 = new byte[param.getMacKeySize() / 8];
				K = new byte[K1.Length + K2.Length];

				kdf.generateBytes(K, 0, K.Length);

				if (V.Length != 0)
				{
					JavaSystem.arraycopy(K, 0, K2, 0, K2.Length);
					JavaSystem.arraycopy(K, K2.Length, K1, 0, K1.Length);
				}
				else
				{
					JavaSystem.arraycopy(K, 0, K1, 0, K1.Length);
					JavaSystem.arraycopy(K, K1.Length, K2, 0, K2.Length);
				}

				// process the message
				M = new byte[K1.Length];

				for (int i = 0; i != K1.Length; i++)
				{
					M[i] = (byte)(in_enc[inOff + V.Length + i] ^ K1[i]);
				}
			}
			else
			{
				// Block cipher mode.        
				K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
				K2 = new byte[param.getMacKeySize() / 8];
				K = new byte[K1.Length + K2.Length];

				kdf.generateBytes(K, 0, K.Length);
				JavaSystem.arraycopy(K, 0, K1, 0, K1.Length);
				JavaSystem.arraycopy(K, K1.Length, K2, 0, K2.Length);

				CipherParameters cp = new KeyParameter(K1);

				// If IV provide use it to initialize the cipher
				if (IV != null)
				{
					cp = new ParametersWithIV(cp, IV);
				}

				cipher.init(false, cp);

				M = new byte[cipher.getOutputSize(inLen - V.Length - mac.getMacSize())];

				// do initial processing
				len = cipher.processBytes(in_enc, inOff + V.Length, inLen - V.Length - mac.getMacSize(), M, 0);
			}

			// Convert the length of the encoding vector into a byte array.
			byte[] P2 = param.getEncodingV();
			byte[] L2 = null;
			if (V.Length != 0)
			{
				L2 = getLengthTag(P2);
			}

			// Verify the MAC.
			int end = inOff + inLen;
			byte[] T1 = Arrays.copyOfRange(in_enc, end - mac.getMacSize(), end);

			byte[] T2 = new byte[T1.Length];
			mac.init(new KeyParameter(K2));
			mac.update(in_enc, inOff + V.Length, inLen - V.Length - T2.Length);

			if (P2 != null)
			{
				mac.update(P2, 0, P2.Length);
			}
			if (V.Length != 0)
			{
				mac.update(L2, 0, L2.Length);
			}
			mac.doFinal(T2, 0);

			if (!Arrays.constantTimeAreEqual(T1, T2))
			{
				throw new InvalidCipherTextException("invalid MAC");
			}

			if (cipher == null)
			{
				return M;
			}
			else
			{
				len += cipher.doFinal(M, len);

				return Arrays.copyOfRange(M, 0, len);
			}
		}


		public virtual byte[] processBlock(byte[] @in, int inOff, int inLen)
		{
			if (forEncryption)
			{
				if (keyPairGenerator != null)
				{
					EphemeralKeyPair ephKeyPair = keyPairGenerator.generate();

					this.privParam = ephKeyPair.getKeyPair().getPrivate();
					this.V = ephKeyPair.getEncodedPublicKey();
				}
			}
			else
			{
				if (keyParser != null)
				{
					ByteArrayInputStream bIn = new ByteArrayInputStream(@in, inOff, inLen);

					try
					{
						this.pubParam = keyParser.readKey(bIn);
					}
					catch (IOException e)
					{
						throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.Message, e);
					}
					catch (IllegalArgumentException e)
					{
						throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.Message, e);
					}

					int encLength = (inLen - bIn.available());
					this.V = Arrays.copyOfRange(@in, inOff, inOff + encLength);
				}
			}

			// Compute the common value and convert to byte array. 
			agree.init(privParam);
			BigInteger z = agree.calculateAgreement(pubParam);
			byte[] Z = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);

			// Create input to KDF.  
			if (V.Length != 0)
			{
				byte[] VZ = Arrays.concatenate(V, Z);
				Arrays.fill(Z, 0);
				Z = VZ;
			}

			try
			{
				// Initialise the KDF.
				KDFParameters kdfParam = new KDFParameters(Z, param.getDerivationV());
				kdf.init(kdfParam);

				return forEncryption ? encryptBlock(@in, inOff, inLen) : decryptBlock(@in, inOff, inLen);
			}
			finally
			{
				Arrays.fill(Z, 0);
			}
		}

		// as described in Shroup's paper and P1363a
		public virtual byte[] getLengthTag(byte[] p2)
		{
			byte[] L2 = new byte[8];
			if (p2 != null)
			{
				Pack.longToBigEndian(p2.Length * 8L, L2, 0);
			}
			return L2;
		}
	}

}