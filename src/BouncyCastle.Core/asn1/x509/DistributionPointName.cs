using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// The DistributionPointName object.
	/// <pre>
	/// DistributionPointName ::= CHOICE {
	///     fullName                 [0] GeneralNames,
	///     nameRelativeToCRLIssuer  [1] RDN
	/// }
	/// </pre>
	/// </summary>
	public class DistributionPointName : ASN1Object, ASN1Choice
	{
		internal ASN1Encodable name;
		internal int type;

		public const int FULL_NAME = 0;
		public const int NAME_RELATIVE_TO_CRL_ISSUER = 1;

		public static DistributionPointName getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1TaggedObject.getInstance(obj, true));
		}

		public static DistributionPointName getInstance(object obj)
		{
			if (obj == null || obj is DistributionPointName)
			{
				return (DistributionPointName)obj;
			}
			else if (obj is ASN1TaggedObject)
			{
				return new DistributionPointName((ASN1TaggedObject)obj);
			}

			throw new IllegalArgumentException("unknown object in factory: " + obj.GetType().getName());
		}

		public DistributionPointName(int type, ASN1Encodable name)
		{
			this.type = type;
			this.name = name;
		}

		public DistributionPointName(GeneralNames name) : this(FULL_NAME, name)
		{
		}

		/// <summary>
		/// Return the tag number applying to the underlying choice.
		/// </summary>
		/// <returns> the tag number for this point name. </returns>
		public virtual int getType()
		{
			return this.type;
		}

		/// <summary>
		/// Return the tagged object inside the distribution point name.
		/// </summary>
		/// <returns> the underlying choice item. </returns>
		public virtual ASN1Encodable getName()
		{
			return (ASN1Encodable)name;
		}

		public DistributionPointName(ASN1TaggedObject obj)
		{
			this.type = obj.getTagNo();

			if (type == 0)
			{
				this.name = GeneralNames.getInstance(obj, false);
			}
			else
			{
				this.name = ASN1Set.getInstance(obj, false);
			}
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERTaggedObject(false, type, name);
		}

		public override string ToString()
		{
			string sep = Strings.lineSeparator();
			StringBuffer buf = new StringBuffer();
			buf.append("DistributionPointName: [");
			buf.append(sep);
			if (type == FULL_NAME)
			{
				appendObject(buf, sep, "fullName", name.ToString());
			}
			else
			{
				appendObject(buf, sep, "nameRelativeToCRLIssuer", name.ToString());
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