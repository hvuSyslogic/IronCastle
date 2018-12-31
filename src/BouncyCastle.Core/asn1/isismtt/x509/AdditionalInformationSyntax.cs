using org.bouncycastle.asn1.x500;

namespace org.bouncycastle.asn1.isismtt.x509
{
	
	/// <summary>
	/// Some other information of non-restrictive nature regarding the usage of this
	/// certificate.
	/// 
	/// <pre>
	///    AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
	/// </pre>
	/// </summary>
	public class AdditionalInformationSyntax : ASN1Object
	{
		private DirectoryString information;

		public static AdditionalInformationSyntax getInstance(object obj)
		{
			if (obj is AdditionalInformationSyntax)
			{
				return (AdditionalInformationSyntax)obj;
			}

			if (obj != null)
			{
				return new AdditionalInformationSyntax(DirectoryString.getInstance(obj));
			}

			return null;
		}

		private AdditionalInformationSyntax(DirectoryString information)
		{
			this.information = information;
		}

		/// <summary>
		/// Constructor from a given details.
		/// </summary>
		/// <param name="information"> The description of the information. </param>
		public AdditionalInformationSyntax(string information) : this(new DirectoryString(information))
		{
		}

		public virtual DirectoryString getInformation()
		{
			return information;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///   AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return information.toASN1Primitive();
		}
	}

}