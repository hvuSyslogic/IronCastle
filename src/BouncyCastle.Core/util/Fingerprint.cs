using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.util
{
	using SHA512tDigest = org.bouncycastle.crypto.digests.SHA512tDigest;
	using SHAKEDigest = org.bouncycastle.crypto.digests.SHAKEDigest;

	/// <summary>
	/// Basic 20 byte finger print class.
	/// </summary>
	public class Fingerprint
	{
		private static char[] encodingTable = new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

		private readonly byte[] fingerprint;

		/// <summary>
		/// Base constructor - use SHAKE-256 (160 bits). This is the recommended one as it is also
		/// produced by the FIPS API.
		/// </summary>
		/// <param name="source"> original data to calculate the fingerprint from. </param>
		public Fingerprint(byte[] source) : this(source, 160)
		{
		}

		/// <summary>
		/// Constructor with length - use SHAKE-256 (bitLength bits). This is the recommended one as it is also
		/// produced by the FIPS API.
		/// </summary>
		/// <param name="source"> original data to calculate the fingerprint from. </param>
		public Fingerprint(byte[] source, int bitLength)
		{
			this.fingerprint = calculateFingerprint(source, bitLength);
		}

		/// <summary>
		/// Base constructor - for backwards compatibility.
		/// </summary>
		/// <param name="source"> original data to calculate the fingerprint from. </param>
		/// <param name="useSHA512t"> use the old SHA512/160 calculation. </param>
		/// @deprecated use the SHAKE only version. 
		public Fingerprint(byte[] source, bool useSHA512t)
		{
			if (useSHA512t)
			{
				this.fingerprint = calculateFingerprintSHA512_160(source);
			}
			else
			{
				this.fingerprint = calculateFingerprint(source);
			}
		}

		public virtual byte[] getFingerprint()
		{
			return Arrays.clone(fingerprint);
		}

		public override string ToString()
		{
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i != fingerprint.Length; i++)
			{
				if (i > 0)
				{
					sb.append(":");
				}
				sb.append(encodingTable[((int)((uint)fingerprint[i] >> 4)) & 0xf]);
				sb.append(encodingTable[fingerprint[i] & 0x0f]);
			}

			return sb.ToString();
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}
			if (o is Fingerprint)
			{
				return Arrays.areEqual(((Fingerprint)o).fingerprint, fingerprint);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(fingerprint);
		}

		/// <summary>
		/// Return a byte array containing a calculated fingerprint for the passed in input data.
		/// This calculation is compatible with the BC FIPS API.
		/// </summary>
		/// <param name="input"> data to base the fingerprint on. </param>
		/// <returns> a byte array containing a 160 bit fingerprint. </returns>
		public static byte[] calculateFingerprint(byte[] input)
		{
			return calculateFingerprint(input, 160);
		}

		/// <summary>
		/// Return a byte array containing a calculated fingerprint for the passed in input data.
		/// This calculation is compatible with the BC FIPS API.
		/// </summary>
		/// <param name="input"> data to base the fingerprint on. </param>
		/// <param name="bitLength"> bit length of finger print to be produced. </param>
		/// <returns> a byte array containing a 20 byte fingerprint. </returns>
		public static byte[] calculateFingerprint(byte[] input, int bitLength)
		{
			if (bitLength % 8 != 0)
			{
				throw new IllegalArgumentException("bitLength must be a multiple of 8");
			}

			SHAKEDigest digest = new SHAKEDigest(256);

			digest.update(input, 0, input.Length);

			byte[] rv = new byte[bitLength / 8];

			digest.doFinal(rv, 0, bitLength / 8);

			return rv;
		}

		/// <summary>
		/// Return a byte array containing a calculated fingerprint for the passed in input data.
		/// The fingerprint is based on SHA512/160.
		/// </summary>
		/// <param name="input"> data to base the fingerprint on. </param>
		/// <returns> a byte array containing a 20 byte fingerprint. </returns>
		/// @deprecated use the SHAKE based version. 
		public static byte[] calculateFingerprintSHA512_160(byte[] input)
		{
			SHA512tDigest digest = new SHA512tDigest(160);

			digest.update(input, 0, input.Length);

			byte[] rv = new byte[digest.getDigestSize()];

			digest.doFinal(rv, 0);

			return rv;
		}
	}

}