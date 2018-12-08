using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.pkcs
{

	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using Arrays = org.bouncycastle.util.Arrays;

	public class MacData : ASN1Object
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		internal DigestInfo digInfo;
		internal byte[] salt;
		internal BigInteger iterationCount;

		public static MacData getInstance(object obj)
		{
			if (obj is MacData)
			{
				return (MacData)obj;
			}
			else if (obj != null)
			{
				return new MacData(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private MacData(ASN1Sequence seq)
		{
			this.digInfo = DigestInfo.getInstance(seq.getObjectAt(0));

			this.salt = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());

			if (seq.size() == 3)
			{
				this.iterationCount = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
			}
			else
			{
				this.iterationCount = ONE;
			}
		}

		public MacData(DigestInfo digInfo, byte[] salt, int iterationCount)
		{
			this.digInfo = digInfo;
			this.salt = Arrays.clone(salt);
			this.iterationCount = BigInteger.valueOf(iterationCount);
		}

		public virtual DigestInfo getMac()
		{
			return digInfo;
		}

		public virtual byte[] getSalt()
		{
			return Arrays.clone(salt);
		}

		public virtual BigInteger getIterationCount()
		{
			return iterationCount;
		}

		/// <summary>
		/// <pre>
		/// MacData ::= SEQUENCE {
		///     mac      DigestInfo,
		///     macSalt  OCTET STRING,
		///     iterations INTEGER DEFAULT 1
		///     -- Note: The default is for historic reasons and its use is deprecated. A
		///     -- higher value, like 1024 is recommended.
		/// </pre> </summary>
		/// <returns> the basic ASN1Primitive construction. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(digInfo);
			v.add(new DEROctetString(salt));

			if (!iterationCount.Equals(ONE))
			{
				v.add(new ASN1Integer(iterationCount));
			}

			return new DERSequence(v);
		}
	}

}