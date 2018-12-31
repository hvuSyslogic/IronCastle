using System;
using org.bouncycastle.asn1.x500.style;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x500
{

	
	/// <summary>
	/// The X.500 Name object.
	/// <pre>
	///     Name ::= CHOICE {
	///                       RDNSequence }
	/// 
	///     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	/// 
	///     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
	/// 
	///     AttributeTypeAndValue ::= SEQUENCE {
	///                                   type  OBJECT IDENTIFIER,
	///                                   value ANY }
	/// </pre>
	/// </summary>
	public class X500Name : ASN1Object, ASN1Choice
	{
		private static X500NameStyle defaultStyle = BCStyle.INSTANCE;

		private bool isHashCodeCalculated;
		private int hashCodeValue;

		private X500NameStyle style;
		private RDN[] rdns;

		/// @deprecated use the getInstance() method that takes a style. 
		public X500Name(X500NameStyle style, X500Name name)
		{
			this.rdns = name.rdns;
			this.style = style;
		}

		/// <summary>
		/// Return a X500Name based on the passed in tagged object.
		/// </summary>
		/// <param name="obj"> tag object holding name. </param>
		/// <param name="explicit"> true if explicitly tagged false otherwise. </param>
		/// <returns> the X500Name </returns>
		public static X500Name getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			// must be true as choice item
			return getInstance(ASN1Sequence.getInstance(obj, true));
		}

		public static X500Name getInstance(object obj)
		{
			if (obj is X500Name)
			{
				return (X500Name)obj;
			}
			else if (obj != null)
			{
				return new X500Name(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static X500Name getInstance(X500NameStyle style, object obj)
		{
			if (obj is X500Name)
			{
				return new X500Name(style, (X500Name)obj);
			}
			else if (obj != null)
			{
				return new X500Name(style, ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor from ASN1Sequence
		/// 
		/// the principal will be a list of constructed sets, each containing an (OID, String) pair.
		/// </summary>
		private X500Name(ASN1Sequence seq) : this(defaultStyle, seq)
		{
		}

		private X500Name(X500NameStyle style, ASN1Sequence seq)
		{
			this.style = style;
			this.rdns = new RDN[seq.size()];

			int index = 0;

			for (Enumeration e = seq.getObjects(); e.hasMoreElements();)
			{
				rdns[index++] = RDN.getInstance(e.nextElement());
			}
		}

		public X500Name(RDN[] rDNs) : this(defaultStyle, rDNs)
		{
		}

		public X500Name(X500NameStyle style, RDN[] rDNs)
		{
			this.rdns = copy(rDNs);
			this.style = style;
		}

		public X500Name(string dirName) : this(defaultStyle, dirName)
		{
		}

		public X500Name(X500NameStyle style, string dirName) : this(style.fromString(dirName))
		{

			this.style = style;
		}

		/// <summary>
		/// return an array of RDNs in structure order.
		/// </summary>
		/// <returns> an array of RDN objects. </returns>
		public virtual RDN[] getRDNs()
		{
			RDN[] tmp = new RDN[this.rdns.Length];

			JavaSystem.arraycopy(rdns, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		/// <summary>
		/// return an array of OIDs contained in the attribute type of each RDN in structure order.
		/// </summary>
		/// <returns> an array, possibly zero length, of ASN1ObjectIdentifiers objects. </returns>
		public virtual ASN1ObjectIdentifier[] getAttributeTypes()
		{
			int count = 0;

			for (int i = 0; i != rdns.Length; i++)
			{
				RDN rdn = rdns[i];

				count += rdn.size();
			}

			ASN1ObjectIdentifier[] res = new ASN1ObjectIdentifier[count];

			count = 0;

			for (int i = 0; i != rdns.Length; i++)
			{
				RDN rdn = rdns[i];

				if (rdn.isMultiValued())
				{
					AttributeTypeAndValue[] attr = rdn.getTypesAndValues();
					for (int j = 0; j != attr.Length; j++)
					{
						res[count++] = attr[j].getType();
					}
				}
				else if (rdn.size() != 0)
				{
					res[count++] = rdn.getFirst().getType();
				}
			}

			return res;
		}

		/// <summary>
		/// return an array of RDNs containing the attribute type given by OID in structure order.
		/// </summary>
		/// <param name="attributeType"> the type OID we are looking for. </param>
		/// <returns> an array, possibly zero length, of RDN objects. </returns>
		public virtual RDN[] getRDNs(ASN1ObjectIdentifier attributeType)
		{
			RDN[] res = new RDN[rdns.Length];
			int count = 0;

			for (int i = 0; i != rdns.Length; i++)
			{
				RDN rdn = rdns[i];

				if (rdn.isMultiValued())
				{
					AttributeTypeAndValue[] attr = rdn.getTypesAndValues();
					for (int j = 0; j != attr.Length; j++)
					{
						if (attr[j].getType().Equals(attributeType))
						{
							res[count++] = rdn;
							break;
						}
					}
				}
				else
				{
					if (rdn.getFirst().getType().Equals(attributeType))
					{
						res[count++] = rdn;
					}
				}
			}

			RDN[] tmp = new RDN[count];

			JavaSystem.arraycopy(res, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		private RDN[] copy(RDN[] rdns)
		{
			RDN[] tmp = new RDN[rdns.Length];

			JavaSystem.arraycopy(rdns, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(rdns);
		}

		public override int GetHashCode()
		{
			if (isHashCodeCalculated)
			{
				return hashCodeValue;
			}

			isHashCodeCalculated = true;

			hashCodeValue = style.calculateHashCode(this);

			return hashCodeValue;
		}

		/// <summary>
		/// test for equality - note: case is ignored.
		/// </summary>
		public override bool Equals(object obj)
		{
			if (obj == this)
			{
				return true;
			}

			if (!(obj is X500Name || obj is ASN1Sequence))
			{
				return false;
			}

			ASN1Primitive derO = ((ASN1Encodable)obj).toASN1Primitive();

			if (this.toASN1Primitive().Equals(derO))
			{
				return true;
			}

			try
			{
				return style.areEqual(this, new X500Name(ASN1Sequence.getInstance(((ASN1Encodable)obj).toASN1Primitive())));
			}
			catch (Exception)
			{
				return false;
			}
		}

		public override string ToString()
		{
			return style.ToString(this);
		}

		/// <summary>
		/// Set the default style for X500Name construction.
		/// </summary>
		/// <param name="style">  an X500NameStyle </param>
		public static void setDefaultStyle(X500NameStyle style)
		{
			if (style == null)
			{
				throw new NullPointerException("cannot set style to null");
			}

			defaultStyle = style;
		}

		/// <summary>
		/// Return the current default style.
		/// </summary>
		/// <returns> default style for X500Name construction. </returns>
		public static X500NameStyle getDefaultStyle()
		{
			return defaultStyle;
		}
	}

}