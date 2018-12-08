using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.agreement.jpake
{

	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Primitives needed for a J-PAKE exchange.
	/// <para>
	/// The recommended way to perform a J-PAKE exchange is by using
	/// two <seealso cref="JPAKEParticipant"/>s.  Internally, those participants
	/// call these primitive operations in <seealso cref="JPAKEUtil"/>.
	/// </para>
	/// <para>
	/// The primitives, however, can be used without a <seealso cref="JPAKEParticipant"/>
	/// if needed.
	/// </para>
	/// </summary>
	public class JPAKEUtil
	{
		internal static readonly BigInteger ZERO = BigInteger.valueOf(0);
		internal static readonly BigInteger ONE = BigInteger.valueOf(1);

		/// <summary>
		/// Return a value that can be used as x1 or x3 during round 1.
		/// <para>
		/// The returned value is a random value in the range <tt>[0, q-1]</tt>.
		/// </para>
		/// </summary>
		public static BigInteger generateX1(BigInteger q, SecureRandom random)
		{
			BigInteger min = ZERO;
			BigInteger max = q.subtract(ONE);
			return BigIntegers.createRandomInRange(min, max, random);
		}

		/// <summary>
		/// Return a value that can be used as x2 or x4 during round 1.
		/// <para>
		/// The returned value is a random value in the range <tt>[1, q-1]</tt>.
		/// </para>
		/// </summary>
		public static BigInteger generateX2(BigInteger q, SecureRandom random)
		{
			BigInteger min = ONE;
			BigInteger max = q.subtract(ONE);
			return BigIntegers.createRandomInRange(min, max, random);
		}

		/// <summary>
		/// Converts the given password to a <seealso cref="BigInteger"/>
		/// for use in arithmetic calculations.
		/// </summary>
		public static BigInteger calculateS(char[] password)
		{
			return new BigInteger(Strings.toUTF8ByteArray(password));
		}

		/// <summary>
		/// Calculate g^x mod p as done in round 1.
		/// </summary>
		public static BigInteger calculateGx(BigInteger p, BigInteger g, BigInteger x)
		{
			return g.modPow(x, p);
		}


		/// <summary>
		/// Calculate ga as done in round 2.
		/// </summary>
		public static BigInteger calculateGA(BigInteger p, BigInteger gx1, BigInteger gx3, BigInteger gx4)
		{
			// ga = g^(x1+x3+x4) = g^x1 * g^x3 * g^x4 
			return gx1.multiply(gx3).multiply(gx4).mod(p);
		}


		/// <summary>
		/// Calculate x2 * s as done in round 2.
		/// </summary>
		public static BigInteger calculateX2s(BigInteger q, BigInteger x2, BigInteger s)
		{
			return x2.multiply(s).mod(q);
		}


		/// <summary>
		/// Calculate A as done in round 2.
		/// </summary>
		public static BigInteger calculateA(BigInteger p, BigInteger q, BigInteger gA, BigInteger x2s)
		{
			// A = ga^(x*s)
			return gA.modPow(x2s, p);
		}

		/// <summary>
		/// Calculate a zero knowledge proof of x using Schnorr's signature.
		/// The returned array has two elements {g^v, r = v-x*h} for x.
		/// </summary>
		public static BigInteger[] calculateZeroKnowledgeProof(BigInteger p, BigInteger q, BigInteger g, BigInteger gx, BigInteger x, string participantId, Digest digest, SecureRandom random)
		{
			BigInteger[] zeroKnowledgeProof = new BigInteger[2];

			/* Generate a random v, and compute g^v */
			BigInteger vMin = ZERO;
			BigInteger vMax = q.subtract(ONE);
			BigInteger v = BigIntegers.createRandomInRange(vMin, vMax, random);

			BigInteger gv = g.modPow(v, p);
			BigInteger h = calculateHashForZeroKnowledgeProof(g, gv, gx, participantId, digest); // h

			zeroKnowledgeProof[0] = gv;
			zeroKnowledgeProof[1] = v.subtract(x.multiply(h)).mod(q); // r = v-x*h

			return zeroKnowledgeProof;
		}

		private static BigInteger calculateHashForZeroKnowledgeProof(BigInteger g, BigInteger gr, BigInteger gx, string participantId, Digest digest)
		{
			digest.reset();

			updateDigestIncludingSize(digest, g);

			updateDigestIncludingSize(digest, gr);

			updateDigestIncludingSize(digest, gx);

			updateDigestIncludingSize(digest, participantId);

			byte[] output = new byte[digest.getDigestSize()];
			digest.doFinal(output, 0);

			return new BigInteger(output);
		}

		/// <summary>
		/// Validates that g^x4 is not 1.
		/// </summary>
		/// <exception cref="CryptoException"> if g^x4 is 1 </exception>
		public static void validateGx4(BigInteger gx4)
		{
			if (gx4.Equals(ONE))
			{
				throw new CryptoException("g^x validation failed.  g^x should not be 1.");
			}
		}

		/// <summary>
		/// Validates that ga is not 1.
		/// <para>
		/// As described by Feng Hao...
		/// </para>
		/// <para>
		/// <blockquote>
		/// Alice could simply check ga != 1 to ensure it is a generator.
		/// In fact, as we will explain in Section 3, (x1 + x3 + x4 ) is random over Zq even in the face of active attacks.
		/// Hence, the probability for ga = 1 is extremely small - on the order of 2^160 for 160-bit q.
		/// </blockquote>
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="CryptoException"> if ga is 1 </exception>
		public static void validateGa(BigInteger ga)
		{
			if (ga.Equals(ONE))
			{
				throw new CryptoException("ga is equal to 1.  It should not be.  The chances of this happening are on the order of 2^160 for a 160-bit q.  Try again.");
			}
		}

		/// <summary>
		/// Validates the zero knowledge proof (generated by
		/// <seealso cref="#calculateZeroKnowledgeProof(BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, String, Digest, SecureRandom)"/>)
		/// is correct.
		/// </summary>
		/// <exception cref="CryptoException"> if the zero knowledge proof is not correct </exception>
		public static void validateZeroKnowledgeProof(BigInteger p, BigInteger q, BigInteger g, BigInteger gx, BigInteger[] zeroKnowledgeProof, string participantId, Digest digest)
		{

			/* sig={g^v,r} */
			BigInteger gv = zeroKnowledgeProof[0];
			BigInteger r = zeroKnowledgeProof[1];

			BigInteger h = calculateHashForZeroKnowledgeProof(g, gv, gx, participantId, digest);
			if (!(gx.compareTo(ZERO) == 1 && gx.compareTo(p) == -1 && gx.modPow(q, p).compareTo(ONE) == 0 && g.modPow(r, p).multiply(gx.modPow(h, p)).mod(p).compareTo(gv) == 0)) // g^v=g^r * g^x^h
			{
				throw new CryptoException("Zero-knowledge proof validation failed");
			}
		}

		/// <summary>
		/// Calculates the keying material, which can be done after round 2 has completed.
		/// A session key must be derived from this key material using a secure key derivation function (KDF).
		/// The KDF used to derive the key is handled externally (i.e. not by <seealso cref="JPAKEParticipant"/>).
		/// <pre>
		/// KeyingMaterial = (B/g^{x2*x4*s})^x2
		/// </pre>
		/// </summary>
		public static BigInteger calculateKeyingMaterial(BigInteger p, BigInteger q, BigInteger gx4, BigInteger x2, BigInteger s, BigInteger B)
		{
			return gx4.modPow(x2.multiply(s).negate().mod(q), p).multiply(B).modPow(x2, p);
		}

		/// <summary>
		/// Validates that the given participant ids are not equal.
		/// (For the J-PAKE exchange, each participant must use a unique id.)
		/// </summary>
		/// <exception cref="CryptoException"> if the participantId strings are equal. </exception>
		public static void validateParticipantIdsDiffer(string participantId1, string participantId2)
		{
			if (participantId1.Equals(participantId2))
			{
				throw new CryptoException("Both participants are using the same participantId (" + participantId1 + "). This is not allowed. " + "Each participant must use a unique participantId.");
			}
		}

		/// <summary>
		/// Validates that the given participant ids are equal.
		/// This is used to ensure that the payloads received from
		/// each round all come from the same participant.
		/// </summary>
		/// <exception cref="CryptoException"> if the participantId strings are equal. </exception>
		public static void validateParticipantIdsEqual(string expectedParticipantId, string actualParticipantId)
		{
			if (!expectedParticipantId.Equals(actualParticipantId))
			{
				throw new CryptoException("Received payload from incorrect partner (" + actualParticipantId + "). Expected to receive payload from " + expectedParticipantId + ".");
			}
		}

		/// <summary>
		/// Validates that the given object is not null.
		/// </summary>
		///  <param name="object"> object in question </param>
		/// <param name="description"> name of the object (to be used in exception message) </param>
		/// <exception cref="NullPointerException"> if the object is null. </exception>
		public static void validateNotNull(object @object, string description)
		{
			if (@object == null)
			{
				throw new NullPointerException(description + " must not be null");
			}
		}

		/// <summary>
		/// Calculates the MacTag (to be used for key confirmation), as defined by
		/// <a href="http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf">NIST SP 800-56A Revision 1</a>,
		/// Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes.
		/// <pre>
		/// MacTag = HMAC(MacKey, MacLen, MacData)
		/// 
		/// MacKey = H(K || "JPAKE_KC")
		/// 
		/// MacData = "KC_1_U" || participantId || partnerParticipantId || gx1 || gx2 || gx3 || gx4
		/// 
		/// Note that both participants use "KC_1_U" because the sender of the round 3 message
		/// is always the initiator for key confirmation.
		/// 
		/// HMAC = <seealso cref="HMac"/> used with the given <seealso cref="Digest"/>
		/// H = The given <seealso cref="Digest"/>
		/// MacLen = length of MacTag
		/// </pre>
		/// </summary>
		public static BigInteger calculateMacTag(string participantId, string partnerParticipantId, BigInteger gx1, BigInteger gx2, BigInteger gx3, BigInteger gx4, BigInteger keyingMaterial, Digest digest)
		{
			byte[] macKey = calculateMacKey(keyingMaterial, digest);

			HMac mac = new HMac(digest);
			byte[] macOutput = new byte[mac.getMacSize()];
			mac.init(new KeyParameter(macKey));

			/*
			 * MacData = "KC_1_U" || participantId_Alice || participantId_Bob || gx1 || gx2 || gx3 || gx4.
			 */
			updateMac(mac, "KC_1_U");
			updateMac(mac, participantId);
			updateMac(mac, partnerParticipantId);
			updateMac(mac, gx1);
			updateMac(mac, gx2);
			updateMac(mac, gx3);
			updateMac(mac, gx4);

			mac.doFinal(macOutput, 0);

			Arrays.fill(macKey, (byte)0);

			return new BigInteger(macOutput);

		}

		/// <summary>
		/// Calculates the MacKey (i.e. the key to use when calculating the MagTag for key confirmation).
		/// <pre>
		/// MacKey = H(K || "JPAKE_KC")
		/// </pre>
		/// </summary>
		private static byte[] calculateMacKey(BigInteger keyingMaterial, Digest digest)
		{
			digest.reset();

			updateDigest(digest, keyingMaterial);
			/*
			 * This constant is used to ensure that the macKey is NOT the same as the derived key.
			 */
			updateDigest(digest, "JPAKE_KC");

			byte[] output = new byte[digest.getDigestSize()];
			digest.doFinal(output, 0);

			return output;
		}

		/// <summary>
		/// Validates the MacTag received from the partner participant.
		/// </summary>
		/// <param name="partnerMacTag"> the MacTag received from the partner. </param>
		/// <exception cref="CryptoException"> if the participantId strings are equal. </exception>
		public static void validateMacTag(string participantId, string partnerParticipantId, BigInteger gx1, BigInteger gx2, BigInteger gx3, BigInteger gx4, BigInteger keyingMaterial, Digest digest, BigInteger partnerMacTag)
		{
			/*
			 * Calculate the expected MacTag using the parameters as the partner
			 * would have used when the partner called calculateMacTag.
			 * 
			 * i.e. basically all the parameters are reversed.
			 * participantId <-> partnerParticipantId
			 *            x1 <-> x3
			 *            x2 <-> x4
			 */
			BigInteger expectedMacTag = calculateMacTag(partnerParticipantId, participantId, gx3, gx4, gx1, gx2, keyingMaterial, digest);

			if (!expectedMacTag.Equals(partnerMacTag))
			{
				throw new CryptoException("Partner MacTag validation failed. " + "Therefore, the password, MAC, or digest algorithm of each participant does not match.");
			}
		}

		private static void updateDigest(Digest digest, BigInteger bigInteger)
		{
			byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
			digest.update(byteArray, 0, byteArray.Length);
			Arrays.fill(byteArray, (byte)0);
		}

		private static void updateDigestIncludingSize(Digest digest, BigInteger bigInteger)
		{
			byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
			digest.update(intToByteArray(byteArray.Length), 0, 4);
			digest.update(byteArray, 0, byteArray.Length);
			Arrays.fill(byteArray, (byte)0);
		}

		private static void updateDigest(Digest digest, string @string)
		{
			byte[] byteArray = Strings.toUTF8ByteArray(@string);
			digest.update(byteArray, 0, byteArray.Length);
			Arrays.fill(byteArray, (byte)0);
		}

		private static void updateDigestIncludingSize(Digest digest, string @string)
		{
			byte[] byteArray = Strings.toUTF8ByteArray(@string);
			digest.update(intToByteArray(byteArray.Length), 0, 4);
			digest.update(byteArray, 0, byteArray.Length);
			Arrays.fill(byteArray, (byte)0);
		}

		private static void updateMac(Mac mac, BigInteger bigInteger)
		{
			byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
			mac.update(byteArray, 0, byteArray.Length);
			Arrays.fill(byteArray, (byte)0);
		}

		private static void updateMac(Mac mac, string @string)
		{
			byte[] byteArray = Strings.toUTF8ByteArray(@string);
			mac.update(byteArray, 0, byteArray.Length);
			Arrays.fill(byteArray, (byte)0);
		}

		private static byte[] intToByteArray(int value)
		{
			return new byte[]{(byte)((int)((uint)value >> 24)), (byte)((int)((uint)value >> 16)), (byte)((int)((uint)value >> 8)), (byte)value};
		}

	}

}