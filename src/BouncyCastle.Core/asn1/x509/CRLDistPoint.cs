using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.x509
{
	using Strings = org.bouncycastle.util.Strings;

	public class CRLDistPoint : ASN1Object
	{
		internal ASN1Sequence seq = null;

		public static CRLDistPoint getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static CRLDistPoint getInstance(object obj)
		{
			if (obj is CRLDistPoint)
			{
				return (CRLDistPoint)obj;
			}
			else if (obj != null)
			{
				return new CRLDistPoint(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private CRLDistPoint(ASN1Sequence seq)
		{
			this.seq = seq;
		}

		public CRLDistPoint(DistributionPoint[] points)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != points.Length; i++)
			{
				v.add(points[i]);
			}

			seq = new DERSequence(v);
		}

		/// <summary>
		/// Return the distribution points making up the sequence.
		/// </summary>
		/// <returns> DistributionPoint[] </returns>
		public virtual DistributionPoint[] getDistributionPoints()
		{
			DistributionPoint[] dp = new DistributionPoint[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				dp[i] = DistributionPoint.getInstance(seq.getObjectAt(i));
			}

			return dp;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// CRLDistPoint ::= SEQUENCE SIZE {1..MAX} OF DistributionPoint
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string sep = Strings.lineSeparator();

			buf.append("CRLDistPoint:");
			buf.append(sep);
			DistributionPoint[] dp = getDistributionPoints();
			for (int i = 0; i != dp.Length; i++)
			{
				buf.append("    ");
				buf.append(dp[i]);
				buf.append(sep);
			}
			return buf.ToString();
		}
	}

}