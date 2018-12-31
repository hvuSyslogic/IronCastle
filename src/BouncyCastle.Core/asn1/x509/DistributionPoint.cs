using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.x509
{
	
	/// <summary>
	/// The DistributionPoint object.
	/// <pre>
	/// DistributionPoint ::= SEQUENCE {
	///      distributionPoint [0] DistributionPointName OPTIONAL,
	///      reasons           [1] ReasonFlags OPTIONAL,
	///      cRLIssuer         [2] GeneralNames OPTIONAL
	/// }
	/// </pre>
	/// </summary>
	public class DistributionPoint : ASN1Object
	{
		internal DistributionPointName distributionPoint;
		internal ReasonFlags reasons;
		internal GeneralNames cRLIssuer;

		public static DistributionPoint getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static DistributionPoint getInstance(object obj)
		{
			if (obj == null || obj is DistributionPoint)
			{
				return (DistributionPoint)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new DistributionPoint((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("Invalid DistributionPoint: " + obj.GetType().getName());
		}

		public DistributionPoint(ASN1Sequence seq)
		{
			for (int i = 0; i != seq.size(); i++)
			{
				ASN1TaggedObject t = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
				switch (t.getTagNo())
				{
				case 0:
					distributionPoint = DistributionPointName.getInstance(t, true);
					break;
				case 1:
					reasons = new ReasonFlags(DERBitString.getInstance(t, false));
					break;
				case 2:
					cRLIssuer = GeneralNames.getInstance(t, false);
					break;
				default:
					throw new IllegalArgumentException("Unknown tag encountered in structure: " + t.getTagNo());
				}
			}
		}

		public DistributionPoint(DistributionPointName distributionPoint, ReasonFlags reasons, GeneralNames cRLIssuer)
		{
			this.distributionPoint = distributionPoint;
			this.reasons = reasons;
			this.cRLIssuer = cRLIssuer;
		}

		public virtual DistributionPointName getDistributionPoint()
		{
			return distributionPoint;
		}

		public virtual ReasonFlags getReasons()
		{
			return reasons;
		}

		public virtual GeneralNames getCRLIssuer()
		{
			return cRLIssuer;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (distributionPoint != null)
			{
				//
				// as this is a CHOICE it must be explicitly tagged
				//
				v.add(new DERTaggedObject(0, distributionPoint));
			}

			if (reasons != null)
			{
				v.add(new DERTaggedObject(false, 1, reasons));
			}

			if (cRLIssuer != null)
			{
				v.add(new DERTaggedObject(false, 2, cRLIssuer));
			}

			return new DERSequence(v);
		}

		public override string ToString()
		{
			string sep = Strings.lineSeparator();
			StringBuffer buf = new StringBuffer();
			buf.append("DistributionPoint: [");
			buf.append(sep);
			if (distributionPoint != null)
			{
				appendObject(buf, sep, "distributionPoint", distributionPoint.ToString());
			}
			if (reasons != null)
			{
				appendObject(buf, sep, "reasons", reasons.ToString());
			}
			if (cRLIssuer != null)
			{
				appendObject(buf, sep, "cRLIssuer", cRLIssuer.ToString());
			}
			buf.append("]");
			buf.append(sep);
			return buf.ToString();
		}

		private void appendObject(StringBuffer buf, string sep, string name, string value)
		{
			string indent = "    ";

			buf.append(indent);
			buf.append(name);
			buf.append(":");
			buf.append(sep);
			buf.append(indent);
			buf.append(indent);
			buf.append(value);
			buf.append(sep);
		}
	}

}