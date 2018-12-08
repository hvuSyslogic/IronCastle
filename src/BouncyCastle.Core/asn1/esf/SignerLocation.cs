using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.esf
{

	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;

	/// <summary>
	/// Signer-Location attribute (RFC3126).
	/// 
	/// <pre>
	///   SignerLocation ::= SEQUENCE {
	///       countryName        [0] DirectoryString OPTIONAL,
	///       localityName       [1] DirectoryString OPTIONAL,
	///       postalAddress      [2] PostalAddress OPTIONAL }
	/// 
	///   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
	/// </pre>
	/// </summary>
	public class SignerLocation : ASN1Object
	{
		private DirectoryString countryName;
		private DirectoryString localityName;
		private ASN1Sequence postalAddress;

		private SignerLocation(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1TaggedObject o = (ASN1TaggedObject)e.nextElement();

				switch (o.getTagNo())
				{
				case 0:
					this.countryName = DirectoryString.getInstance(o, true);
					break;
				case 1:
					this.localityName = DirectoryString.getInstance(o, true);
					break;
				case 2:
					if (o.isExplicit())
					{
						this.postalAddress = ASN1Sequence.getInstance(o, true);
					}
					else // handle erroneous implicitly tagged sequences
					{
						this.postalAddress = ASN1Sequence.getInstance(o, false);
					}
					if (postalAddress != null && postalAddress.size() > 6)
					{
						throw new IllegalArgumentException("postal address must contain less than 6 strings");
					}
					break;
				default:
					throw new IllegalArgumentException("illegal tag");
				}
			}
		}

		private SignerLocation(DirectoryString countryName, DirectoryString localityName, ASN1Sequence postalAddress)
		{
			if (postalAddress != null && postalAddress.size() > 6)
			{
				throw new IllegalArgumentException("postal address must contain less than 6 strings");
			}

			this.countryName = countryName;
			this.localityName = localityName;
			this.postalAddress = postalAddress;
		}

		public SignerLocation(DirectoryString countryName, DirectoryString localityName, DirectoryString[] postalAddress) : this(countryName, localityName, new DERSequence(postalAddress))
		{
		}

		public SignerLocation(DERUTF8String countryName, DERUTF8String localityName, ASN1Sequence postalAddress) : this(DirectoryString.getInstance(countryName), DirectoryString.getInstance(localityName), postalAddress)
		{
		}

		public static SignerLocation getInstance(object obj)
		{
			if (obj == null || obj is SignerLocation)
			{
				return (SignerLocation)obj;
			}

			return new SignerLocation(ASN1Sequence.getInstance(obj));
		}

		/// <summary>
		/// Return the countryName DirectoryString
		/// </summary>
		/// <returns> the countryName, null if absent. </returns>
		public virtual DirectoryString getCountry()
		{
			return countryName;
		}

		/// <summary>
		/// Return the localityName DirectoryString
		/// </summary>
		/// <returns> the localityName, null if absent. </returns>
		public virtual DirectoryString getLocality()
		{
			return localityName;
		}

		/// <summary>
		/// Return the postalAddress DirectoryStrings
		/// </summary>
		/// <returns> the postalAddress, null if absent. </returns>
		public virtual DirectoryString[] getPostal()
		{
			if (postalAddress == null)
			{
				return null;
			}

			DirectoryString[] dirStrings = new DirectoryString[postalAddress.size()];
			for (int i = 0; i != dirStrings.Length; i++)
			{
				dirStrings[i] = DirectoryString.getInstance(postalAddress.getObjectAt(i));
			}

			return dirStrings;
		}

		/// @deprecated use getCountry() 
		public virtual DERUTF8String getCountryName()
		{
			if (countryName == null)
			{
				return null;
			}
			return new DERUTF8String(getCountry().getString());
		}

		/// @deprecated use getLocality() 
		public virtual DERUTF8String getLocalityName()
		{
			if (localityName == null)
			{
				return null;
			}
			return new DERUTF8String(getLocality().getString());
		}

		public virtual ASN1Sequence getPostalAddress()
		{
			return postalAddress;
		}

		/// <summary>
		/// <pre>
		///   SignerLocation ::= SEQUENCE {
		///       countryName        [0] DirectoryString OPTIONAL,
		///       localityName       [1] DirectoryString OPTIONAL,
		///       postalAddress      [2] PostalAddress OPTIONAL }
		/// 
		///   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
		/// 
		///   DirectoryString ::= CHOICE {
		///         teletexString           TeletexString (SIZE (1..MAX)),
		///         printableString         PrintableString (SIZE (1..MAX)),
		///         universalString         UniversalString (SIZE (1..MAX)),
		///         utf8String              UTF8String (SIZE (1.. MAX)),
		///         bmpString               BMPString (SIZE (1..MAX)) }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (countryName != null)
			{
				v.add(new DERTaggedObject(true, 0, countryName));
			}

			if (localityName != null)
			{
				v.add(new DERTaggedObject(true, 1, localityName));
			}

			if (postalAddress != null)
			{
				v.add(new DERTaggedObject(true, 2, postalAddress));
			}

			return new DERSequence(v);
		}
	}

}