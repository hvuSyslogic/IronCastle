using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// <pre>
	/// IssuingDistributionPoint ::= SEQUENCE { 
	///   distributionPoint          [0] DistributionPointName OPTIONAL, 
	///   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE, 
	///   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE, 
	///   onlySomeReasons            [3] ReasonFlags OPTIONAL, 
	///   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
	///   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
	/// </pre>
	/// </summary>
	public class IssuingDistributionPoint : ASN1Object
	{
		private DistributionPointName distributionPoint;

//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private bool onlyContainsUserCerts_Renamed;

//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private bool onlyContainsCACerts_Renamed;

		private ReasonFlags onlySomeReasons;

		private bool indirectCRL;

//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private bool onlyContainsAttributeCerts_Renamed;

		private ASN1Sequence seq;

		public static IssuingDistributionPoint getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static IssuingDistributionPoint getInstance(object obj)
		{
			if (obj is IssuingDistributionPoint)
			{
				return (IssuingDistributionPoint)obj;
			}
			else if (obj != null)
			{
				return new IssuingDistributionPoint(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor from given details.
		/// </summary>
		/// <param name="distributionPoint">
		///            May contain an URI as pointer to most current CRL. </param>
		/// <param name="onlyContainsUserCerts"> Covers revocation information for end certificates. </param>
		/// <param name="onlyContainsCACerts"> Covers revocation information for CA certificates.
		/// </param>
		/// <param name="onlySomeReasons">
		///            Which revocation reasons does this point cover. </param>
		/// <param name="indirectCRL">
		///            If <code>true</code> then the CRL contains revocation
		///            information about certificates ssued by other CAs. </param>
		/// <param name="onlyContainsAttributeCerts"> Covers revocation information for attribute certificates. </param>
		public IssuingDistributionPoint(DistributionPointName distributionPoint, bool onlyContainsUserCerts, bool onlyContainsCACerts, ReasonFlags onlySomeReasons, bool indirectCRL, bool onlyContainsAttributeCerts)
		{
			this.distributionPoint = distributionPoint;
			this.indirectCRL = indirectCRL;
			this.onlyContainsAttributeCerts_Renamed = onlyContainsAttributeCerts;
			this.onlyContainsCACerts_Renamed = onlyContainsCACerts;
			this.onlyContainsUserCerts_Renamed = onlyContainsUserCerts;
			this.onlySomeReasons = onlySomeReasons;

			ASN1EncodableVector vec = new ASN1EncodableVector();
			if (distributionPoint != null)
			{ // CHOICE item so explicitly tagged
				vec.add(new DERTaggedObject(true, 0, distributionPoint));
			}
			if (onlyContainsUserCerts)
			{
				vec.add(new DERTaggedObject(false, 1, ASN1Boolean.getInstance(true)));
			}
			if (onlyContainsCACerts)
			{
				vec.add(new DERTaggedObject(false, 2, ASN1Boolean.getInstance(true)));
			}
			if (onlySomeReasons != null)
			{
				vec.add(new DERTaggedObject(false, 3, onlySomeReasons));
			}
			if (indirectCRL)
			{
				vec.add(new DERTaggedObject(false, 4, ASN1Boolean.getInstance(true)));
			}
			if (onlyContainsAttributeCerts)
			{
				vec.add(new DERTaggedObject(false, 5, ASN1Boolean.getInstance(true)));
			}

			seq = new DERSequence(vec);
		}

		/// <summary>
		/// Shorthand Constructor from given details.
		/// </summary>
		/// <param name="distributionPoint">
		///            May contain an URI as pointer to most current CRL. </param>
		/// <param name="indirectCRL">
		///            If <code>true</code> then the CRL contains revocation
		///            information about certificates ssued by other CAs. </param>
		/// <param name="onlyContainsAttributeCerts"> Covers revocation information for attribute certificates. </param>
		public IssuingDistributionPoint(DistributionPointName distributionPoint, bool indirectCRL, bool onlyContainsAttributeCerts) : this(distributionPoint, false, false, null, indirectCRL, onlyContainsAttributeCerts)
		{
		}

		/// <summary>
		/// Constructor from ASN1Sequence
		/// </summary>
		private IssuingDistributionPoint(ASN1Sequence seq)
		{
			this.seq = seq;

			for (int i = 0; i != seq.size(); i++)
			{
				ASN1TaggedObject o = ASN1TaggedObject.getInstance(seq.getObjectAt(i));

				switch (o.getTagNo())
				{
				case 0:
														// CHOICE so explicit
					distributionPoint = DistributionPointName.getInstance(o, true);
					break;
				case 1:
					onlyContainsUserCerts_Renamed = ASN1Boolean.getInstance(o, false).isTrue();
					break;
				case 2:
					onlyContainsCACerts_Renamed = ASN1Boolean.getInstance(o, false).isTrue();
					break;
				case 3:
					onlySomeReasons = new ReasonFlags(ReasonFlags.getInstance(o, false));
					break;
				case 4:
					indirectCRL = ASN1Boolean.getInstance(o, false).isTrue();
					break;
				case 5:
					onlyContainsAttributeCerts_Renamed = ASN1Boolean.getInstance(o, false).isTrue();
					break;
				default:
					throw new IllegalArgumentException("unknown tag in IssuingDistributionPoint");
				}
			}
		}

		public virtual bool onlyContainsUserCerts()
		{
			return onlyContainsUserCerts_Renamed;
		}

		public virtual bool onlyContainsCACerts()
		{
			return onlyContainsCACerts_Renamed;
		}

		public virtual bool isIndirectCRL()
		{
			return indirectCRL;
		}

		public virtual bool onlyContainsAttributeCerts()
		{
			return onlyContainsAttributeCerts_Renamed;
		}

		/// <returns> Returns the distributionPoint. </returns>
		public virtual DistributionPointName getDistributionPoint()
		{
			return distributionPoint;
		}

		/// <returns> Returns the onlySomeReasons. </returns>
		public virtual ReasonFlags getOnlySomeReasons()
		{
			return onlySomeReasons;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}

		public override string ToString()
		{
			string sep = Strings.lineSeparator();
			StringBuffer buf = new StringBuffer();

			buf.append("IssuingDistributionPoint: [");
			buf.append(sep);
			if (distributionPoint != null)
			{
				appendObject(buf, sep, "distributionPoint", distributionPoint.ToString());
			}
			if (onlyContainsUserCerts_Renamed)
			{
				appendObject(buf, sep, "onlyContainsUserCerts", booleanToString(onlyContainsUserCerts_Renamed));
			}
			if (onlyContainsCACerts_Renamed)
			{
				appendObject(buf, sep, "onlyContainsCACerts", booleanToString(onlyContainsCACerts_Renamed));
			}
			if (onlySomeReasons != null)
			{
				appendObject(buf, sep, "onlySomeReasons", onlySomeReasons.ToString());
			}
			if (onlyContainsAttributeCerts_Renamed)
			{
				appendObject(buf, sep, "onlyContainsAttributeCerts", booleanToString(onlyContainsAttributeCerts_Renamed));
			}
			if (indirectCRL)
			{
				appendObject(buf, sep, "indirectCRL", booleanToString(indirectCRL));
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

		private string booleanToString(bool value)
		{
			return value ? "true" : "false";
		}
	}

}