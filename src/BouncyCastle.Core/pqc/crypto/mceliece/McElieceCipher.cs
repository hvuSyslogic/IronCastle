using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.pqc.math.linearalgebra;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.mceliece
{

											
	/// <summary>
	/// This class implements the McEliece Public Key cryptosystem (McEliecePKCS). It
	/// was first described in R.J. McEliece, "A public key cryptosystem based on
	/// algebraic coding theory", DSN progress report, 42-44:114-116, 1978. The
	/// McEliecePKCS is the first cryptosystem which is based on error correcting
	/// codes. The trapdoor for the McEliece cryptosystem using Goppa codes is the
	/// knowledge of the Goppa polynomial used to generate the code.
	/// </summary>
	public class McElieceCipher : MessageEncryptor
	{

		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.1";


		// the source of randomness
		private SecureRandom sr;

		// the McEliece main parameters
		private int n, k, t;

		// The maximum number of bytes the cipher can decrypt
		public int maxPlainTextSize;

		// The maximum number of bytes the cipher can encrypt
		public int cipherTextSize;

		private McElieceKeyParameters key;
		private bool forEncryption;


		public virtual void init(bool forEncryption, CipherParameters param)
		{
			this.forEncryption = forEncryption;
			if (forEncryption)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.sr = rParam.getRandom();
					this.key = (McEliecePublicKeyParameters)rParam.getParameters();
					this.initCipherEncrypt((McEliecePublicKeyParameters)key);

				}
				else
				{
					this.sr = CryptoServicesRegistrar.getSecureRandom();
					this.key = (McEliecePublicKeyParameters)param;
					this.initCipherEncrypt((McEliecePublicKeyParameters)key);
				}
			}
			else
			{
				this.key = (McEliecePrivateKeyParameters)param;
				this.initCipherDecrypt((McEliecePrivateKeyParameters)key);
			}

		}

		/// <summary>
		/// Return the key size of the given key object.
		/// </summary>
		/// <param name="key"> the McElieceKeyParameters object </param>
		/// <returns> the keysize of the given key object </returns>

		public virtual int getKeySize(McElieceKeyParameters key)
		{

			if (key is McEliecePublicKeyParameters)
			{
				return ((McEliecePublicKeyParameters)key).getN();

			}
			if (key is McEliecePrivateKeyParameters)
			{
				return ((McEliecePrivateKeyParameters)key).getN();
			}
			throw new IllegalArgumentException("unsupported type");

		}


		private void initCipherEncrypt(McEliecePublicKeyParameters pubKey)
		{
			this.sr = sr != null ? sr : CryptoServicesRegistrar.getSecureRandom();
			n = pubKey.getN();
			k = pubKey.getK();
			t = pubKey.getT();
			cipherTextSize = n >> 3;
			maxPlainTextSize = (k >> 3);
		}


		private void initCipherDecrypt(McEliecePrivateKeyParameters privKey)
		{
			n = privKey.getN();
			k = privKey.getK();

			maxPlainTextSize = (k >> 3);
			cipherTextSize = n >> 3;
		}

		/// <summary>
		/// Encrypt a plain text.
		/// </summary>
		/// <param name="input"> the plain text </param>
		/// <returns> the cipher text </returns>
		public virtual byte[] messageEncrypt(byte[] input)
		{
			if (!forEncryption)
			{
				throw new IllegalStateException("cipher initialised for decryption");
			}
			GF2Vector m = computeMessageRepresentative(input);
			GF2Vector z = new GF2Vector(n, t, sr);

			GF2Matrix g = ((McEliecePublicKeyParameters)key).getG();
			Vector mG = g.leftMultiply(m);
			GF2Vector mGZ = (GF2Vector)mG.add(z);

			return mGZ.getEncoded();
		}

		private GF2Vector computeMessageRepresentative(byte[] input)
		{
			byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
			JavaSystem.arraycopy(input, 0, data, 0, input.Length);
			data[input.Length] = 0x01;
			return GF2Vector.OS2VP(k, data);
		}

		/// <summary>
		/// Decrypt a cipher text.
		/// </summary>
		/// <param name="input"> the cipher text </param>
		/// <returns> the plain text </returns>
		/// <exception cref="InvalidCipherTextException"> if the cipher text is invalid. </exception>
		public virtual byte[] messageDecrypt(byte[] input)
		{
			if (forEncryption)
			{
				throw new IllegalStateException("cipher initialised for decryption");
			}

			GF2Vector vec = GF2Vector.OS2VP(n, input);
			McEliecePrivateKeyParameters privKey = (McEliecePrivateKeyParameters)key;
			GF2mField field = privKey.getField();
			PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
			GF2Matrix sInv = privKey.getSInv();
			Permutation p1 = privKey.getP1();
			Permutation p2 = privKey.getP2();
			GF2Matrix h = privKey.getH();
			PolynomialGF2mSmallM[] qInv = privKey.getQInv();

			// compute permutation P = P1 * P2
			Permutation p = p1.rightMultiply(p2);

			// compute P^-1
			Permutation pInv = p.computeInverse();

			// compute c P^-1
			GF2Vector cPInv = (GF2Vector)vec.multiply(pInv);

			// compute syndrome of c P^-1
			GF2Vector syndrome = (GF2Vector)h.rightMultiply(cPInv);

			// decode syndrome
			GF2Vector z = GoppaCode.syndromeDecode(syndrome, field, gp, qInv);
			GF2Vector mSG = (GF2Vector)cPInv.add(z);

			// multiply codeword with P1 and error vector with P
			mSG = (GF2Vector)mSG.multiply(p1);
			z = (GF2Vector)z.multiply(p);

			// extract mS (last k columns of mSG)
			GF2Vector mS = mSG.extractRightVector(k);

			// compute plaintext vector
			GF2Vector mVec = (GF2Vector)sInv.leftMultiply(mS);

			// compute and return plaintext
			return computeMessage(mVec);
		}

		private byte[] computeMessage(GF2Vector mr)
		{
			byte[] mrBytes = mr.getEncoded();
			// find first non-zero byte
			int index;
			for (index = mrBytes.Length - 1; index >= 0 && mrBytes[index] == 0; index--)
			{
				;
			}

			// check if padding byte is valid
			if (index < 0 || mrBytes[index] != 0x01)
			{
				throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
			}

			// extract and return message
			byte[] mBytes = new byte[index];
			JavaSystem.arraycopy(mrBytes, 0, mBytes, 0, index);
			return mBytes;
		}


	}

}