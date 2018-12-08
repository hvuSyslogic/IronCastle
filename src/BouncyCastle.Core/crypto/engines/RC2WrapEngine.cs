using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{

	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Wrap keys according to RFC 3217 - RC2 mechanism
	/// </summary>
	public class RC2WrapEngine : Wrapper
	{
	   /// <summary>
	   /// Field engine </summary>
	   private CBCBlockCipher engine;

	   /// <summary>
	   /// Field param </summary>
	   private CipherParameters param;

	   /// <summary>
	   /// Field paramPlusIV </summary>
	   private ParametersWithIV paramPlusIV;

	   /// <summary>
	   /// Field iv </summary>
	   private byte[] iv;

	   /// <summary>
	   /// Field forWrapping </summary>
	   private bool forWrapping;

	   private SecureRandom sr;

	   /// <summary>
	   /// Field IV2 </summary>
	   private static readonly byte[] IV2 = new byte[] {(byte) 0x4a, unchecked((byte) 0xdd), unchecked((byte) 0xa2), (byte) 0x2c, (byte) 0x79, unchecked((byte) 0xe8), (byte) 0x21, (byte) 0x05};

		//
		// checksum digest
		//
		internal Digest sha1 = DigestFactory.createSHA1();
		internal byte[] digest = new byte[20];

	   /// <summary>
	   /// Method init
	   /// </summary>
	   /// <param name="forWrapping"> true if for wrapping, false for unwrap. </param>
	   /// <param name="param"> parameters for wrap/unwrapping (iv required for unwrap). </param>
	   public virtual void init(bool forWrapping, CipherParameters param)
	   {
			this.forWrapping = forWrapping;
			this.engine = new CBCBlockCipher(new RC2Engine());

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom pWithR = (ParametersWithRandom)param;
				sr = pWithR.getRandom();
				param = pWithR.getParameters();
			}
			else
			{
				sr = CryptoServicesRegistrar.getSecureRandom();
			}

			if (param is ParametersWithIV)
			{
				this.paramPlusIV = (ParametersWithIV)param;
				this.iv = this.paramPlusIV.getIV();
				this.param = this.paramPlusIV.getParameters();

				if (this.forWrapping)
				{
					if ((this.iv == null) || (this.iv.Length != 8))
					{
						throw new IllegalArgumentException("IV is not 8 octets");
					}
				}
				else
				{
					throw new IllegalArgumentException("You should not supply an IV for unwrapping");
				}
			}
			else
			{
				this.param = param;

				if (this.forWrapping)
				{

					// Hm, we have no IV but we want to wrap ?!?
					// well, then we have to create our own IV.
					this.iv = new byte[8];

					sr.nextBytes(iv);

					this.paramPlusIV = new ParametersWithIV(this.param, this.iv);
				}
			}

	   }

	   /// <summary>
	   /// Method getAlgorithmName
	   /// </summary>
	   /// <returns> the algorithm name "RC2". </returns>
	   public virtual string getAlgorithmName()
	   {
		  return "RC2";
	   }

	   /// <summary>
	   /// Method wrap
	   /// </summary>
	   /// <param name="in"> byte array containing the key. </param>
	   /// <param name="inOff"> offset into in array that the key data starts at. </param>
	   /// <param name="inLen"> length of key data. </param>
	   /// <returns> the wrapped bytes. </returns>
	   public virtual byte[] wrap(byte[] @in, int inOff, int inLen)
	   {

			if (!forWrapping)
			{
				throw new IllegalStateException("Not initialized for wrapping");
			}

			int length = inLen + 1;
			if ((length % 8) != 0)
			{
				length += 8 - (length % 8);
			}

			byte[] keyToBeWrapped = new byte[length];

			keyToBeWrapped[0] = (byte)inLen;
			JavaSystem.arraycopy(@in, inOff, keyToBeWrapped, 1, inLen);

			byte[] pad = new byte[keyToBeWrapped.Length - inLen - 1];

			if (pad.Length > 0)
			{
				sr.nextBytes(pad);
				JavaSystem.arraycopy(pad, 0, keyToBeWrapped, inLen + 1, pad.Length);
			}

			// Compute the CMS Key Checksum, (section 5.6.1), call this CKS.
			byte[] CKS = calculateCMSKeyChecksum(keyToBeWrapped);

			// Let WKCKS = WK || CKS where || is concatenation.
			byte[] WKCKS = new byte[keyToBeWrapped.Length + CKS.Length];

			JavaSystem.arraycopy(keyToBeWrapped, 0, WKCKS, 0, keyToBeWrapped.Length);
			JavaSystem.arraycopy(CKS, 0, WKCKS, keyToBeWrapped.Length, CKS.Length);

			// Encrypt WKCKS in CBC mode using KEK as the key and IV as the
			// initialization vector. Call the results TEMP1.
			byte[] TEMP1 = new byte[WKCKS.Length];

			JavaSystem.arraycopy(WKCKS, 0, TEMP1, 0, WKCKS.Length);

			int noOfBlocks = WKCKS.Length / engine.getBlockSize();
			int extraBytes = WKCKS.Length % engine.getBlockSize();

			if (extraBytes != 0)
			{
				throw new IllegalStateException("Not multiple of block length");
			}

			engine.init(true, paramPlusIV);

			for (int i = 0; i < noOfBlocks; i++)
			{
				int currentBytePos = i * engine.getBlockSize();

				engine.processBlock(TEMP1, currentBytePos, TEMP1, currentBytePos);
			}

			// Left TEMP2 = IV || TEMP1.
			byte[] TEMP2 = new byte[this.iv.Length + TEMP1.Length];

			JavaSystem.arraycopy(this.iv, 0, TEMP2, 0, this.iv.Length);
			JavaSystem.arraycopy(TEMP1, 0, TEMP2, this.iv.Length, TEMP1.Length);

			// Reverse the order of the octets in TEMP2 and call the result TEMP3.
			byte[] TEMP3 = new byte[TEMP2.Length];

			for (int i = 0; i < TEMP2.Length; i++)
			{
				TEMP3[i] = TEMP2[TEMP2.Length - (i + 1)];
			}

			// Encrypt TEMP3 in CBC mode using the KEK and an initialization vector
			// of 0x 4a dd a2 2c 79 e8 21 05. The resulting cipher text is the
			// desired
			// result. It is 40 octets long if a 168 bit key is being wrapped.
			ParametersWithIV param2 = new ParametersWithIV(this.param, IV2);

			this.engine.init(true, param2);

			for (int i = 0; i < noOfBlocks + 1; i++)
			{
				int currentBytePos = i * engine.getBlockSize();

				engine.processBlock(TEMP3, currentBytePos, TEMP3, currentBytePos);
			}

			return TEMP3;
	   }

	   /// <summary>
	   /// Method unwrap
	   /// </summary>
	   /// <param name="in"> byte array containing the wrapped key. </param>
	   /// <param name="inOff"> offset into in array that the wrapped key starts at. </param>
	   /// <param name="inLen"> length of wrapped key data. </param>
	   /// <returns> the unwrapped bytes. </returns>
	   /// <exception cref="InvalidCipherTextException"> </exception>
	   public virtual byte[] unwrap(byte[] @in, int inOff, int inLen)
	   {

			if (forWrapping)
			{
				throw new IllegalStateException("Not set for unwrapping");
			}

			if (@in == null)
			{
				throw new InvalidCipherTextException("Null pointer as ciphertext");
			}

			if (inLen % engine.getBlockSize() != 0)
			{
				throw new InvalidCipherTextException("Ciphertext not multiple of " + engine.getBlockSize());
			}

			/*
			 * // Check if the length of the cipher text is reasonable given the key //
			 * type. It must be 40 bytes for a 168 bit key and either 32, 40, or //
			 * 48 bytes for a 128, 192, or 256 bit key. If the length is not
			 * supported // or inconsistent with the algorithm for which the key is
			 * intended, // return error. // // we do not accept 168 bit keys. it
			 * has to be 192 bit. int lengthA = (estimatedKeyLengthInBit / 8) + 16;
			 * int lengthB = estimatedKeyLengthInBit % 8;
			 * 
			 * if ((lengthA != keyToBeUnwrapped.length) || (lengthB != 0)) { throw
			 * new XMLSecurityException("empty"); }
			 */

			// Decrypt the cipher text with TRIPLedeS in CBC mode using the KEK
			// and an initialization vector (IV) of 0x4adda22c79e82105. Call the
			// output TEMP3.
			ParametersWithIV param2 = new ParametersWithIV(this.param, IV2);

			this.engine.init(false, param2);

			byte[] TEMP3 = new byte[inLen];

			JavaSystem.arraycopy(@in, inOff, TEMP3, 0, inLen);

			for (int i = 0; i < (TEMP3.Length / engine.getBlockSize()); i++)
			{
				int currentBytePos = i * engine.getBlockSize();

				engine.processBlock(TEMP3, currentBytePos, TEMP3, currentBytePos);
			}

			// Reverse the order of the octets in TEMP3 and call the result TEMP2.
			byte[] TEMP2 = new byte[TEMP3.Length];

			for (int i = 0; i < TEMP3.Length; i++)
			{
				TEMP2[i] = TEMP3[TEMP3.Length - (i + 1)];
			}

			// Decompose TEMP2 into IV, the first 8 octets, and TEMP1, the remaining
			// octets.
			this.iv = new byte[8];

			byte[] TEMP1 = new byte[TEMP2.Length - 8];

			JavaSystem.arraycopy(TEMP2, 0, this.iv, 0, 8);
			JavaSystem.arraycopy(TEMP2, 8, TEMP1, 0, TEMP2.Length - 8);

			// Decrypt TEMP1 using TRIPLedeS in CBC mode using the KEK and the IV
			// found in the previous step. Call the result WKCKS.
			this.paramPlusIV = new ParametersWithIV(this.param, this.iv);

			this.engine.init(false, this.paramPlusIV);

			byte[] LCEKPADICV = new byte[TEMP1.Length];

			JavaSystem.arraycopy(TEMP1, 0, LCEKPADICV, 0, TEMP1.Length);

			for (int i = 0; i < (LCEKPADICV.Length / engine.getBlockSize()); i++)
			{
				int currentBytePos = i * engine.getBlockSize();

				engine.processBlock(LCEKPADICV, currentBytePos, LCEKPADICV, currentBytePos);
			}

			// Decompose LCEKPADICV. CKS is the last 8 octets and WK, the wrapped
			// key, are
			// those octets before the CKS.
			byte[] result = new byte[LCEKPADICV.Length - 8];
			byte[] CKStoBeVerified = new byte[8];

			JavaSystem.arraycopy(LCEKPADICV, 0, result, 0, LCEKPADICV.Length - 8);
			JavaSystem.arraycopy(LCEKPADICV, LCEKPADICV.Length - 8, CKStoBeVerified, 0, 8);

			// Calculate a CMS Key Checksum, (section 5.6.1), over the WK and
			// compare
			// with the CKS extracted in the above step. If they are not equal,
			// return error.
			if (!checkCMSKeyChecksum(result, CKStoBeVerified))
			{
				throw new InvalidCipherTextException("Checksum inside ciphertext is corrupted");
			}

			if ((result.Length - ((result[0] & 0xff) + 1)) > 7)
			{
				throw new InvalidCipherTextException("too many pad bytes (" + (result.Length - ((result[0] & 0xff) + 1)) + ")");
			}

			// CEK is the wrapped key, now extracted for use in data decryption.
			byte[] CEK = new byte[result[0]];
			JavaSystem.arraycopy(result, 1, CEK, 0, CEK.Length);
			return CEK;
	   }

		/*
		 * Some key wrap algorithms make use of the Key Checksum defined
		 * in CMS [CMS-Algorithms]. This is used to provide an integrity
		 * check value for the key being wrapped. The algorithm is
		 *
		 * - Compute the 20 octet SHA-1 hash on the key being wrapped.
		 * - Use the first 8 octets of this hash as the checksum value.
		 *
		 * For details see  http://www.w3.org/TR/xmlenc-core/#sec-CMSKeyChecksum
		 */
		private byte[] calculateCMSKeyChecksum(byte[] key)
		{
			byte[] result = new byte[8];

			sha1.update(key, 0, key.Length);
			sha1.doFinal(digest, 0);

			JavaSystem.arraycopy(digest, 0, result, 0, 8);

			return result;
		}

		/*
		 * For details see  http://www.w3.org/TR/xmlenc-core/#sec-CMSKeyChecksum
		 */
		private bool checkCMSKeyChecksum(byte[] key, byte[] checksum)
		{
			return Arrays.constantTimeAreEqual(calculateCMSKeyChecksum(key), checksum);
		}
	}

}