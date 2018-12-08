using org.bouncycastle.asn1.isismtt;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.isismtt.x509
{

	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;

	/// <summary>
	/// Names of authorities which are responsible for the administration of title
	/// registers.
	/// 
	/// <pre>
	///             NamingAuthority ::= SEQUENCE 
	///             {
	///               namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
	///               namingAuthorityUrl IA5String OPTIONAL,
	///               namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
	///             }
	/// </pre> </summary>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
	///  </seealso>
	public class NamingAuthority : ASN1Object
	{

		/// <summary>
		/// Profession OIDs should always be defined under the OID branch of the
		/// responsible naming authority. At the time of this writing, the work group
		/// �Recht, Wirtschaft, Steuern� (�Law, Economy, Taxes�) is registered as the
		/// first naming authority under the OID id-isismtt-at-namingAuthorities.
		/// </summary>
		public static readonly ASN1ObjectIdentifier id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern = new ASN1ObjectIdentifier(ISISMTTObjectIdentifiers_Fields.id_isismtt_at_namingAuthorities + ".1");

		private ASN1ObjectIdentifier namingAuthorityId;
		private string namingAuthorityUrl;
		private DirectoryString namingAuthorityText;

		public static NamingAuthority getInstance(object obj)
		{
			if (obj == null || obj is NamingAuthority)
			{
				return (NamingAuthority)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new NamingAuthority((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		public static NamingAuthority getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <pre>
		///             NamingAuthority ::= SEQUENCE
		///             {
		///               namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
		///               namingAuthorityUrl IA5String OPTIONAL,
		///               namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		///             }
		/// </pre>
		/// </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private NamingAuthority(ASN1Sequence seq)
		{

			if (seq.size() > 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			Enumeration e = seq.getObjects();

			if (e.hasMoreElements())
			{
				ASN1Encodable o = (ASN1Encodable)e.nextElement();
				if (o is ASN1ObjectIdentifier)
				{
					namingAuthorityId = (ASN1ObjectIdentifier)o;
				}
				else if (o is DERIA5String)
				{
					namingAuthorityUrl = DERIA5String.getInstance(o).getString();
				}
				else if (o is ASN1String)
				{
					namingAuthorityText = DirectoryString.getInstance(o);
				}
				else
				{
					throw new IllegalArgumentException("Bad object encountered: " + o.GetType());
				}
			}
			if (e.hasMoreElements())
			{
				ASN1Encodable o = (ASN1Encodable)e.nextElement();
				if (o is DERIA5String)
				{
					namingAuthorityUrl = DERIA5String.getInstance(o).getString();
				}
				else if (o is ASN1String)
				{
					namingAuthorityText = DirectoryString.getInstance(o);
				}
				else
				{
					throw new IllegalArgumentException("Bad object encountered: " + o.GetType());
				}
			}
			if (e.hasMoreElements())
			{
				ASN1Encodable o = (ASN1Encodable)e.nextElement();
				if (o is ASN1String)
				{
					namingAuthorityText = DirectoryString.getInstance(o);
				}
				else
				{
					throw new IllegalArgumentException("Bad object encountered: " + o.GetType());
				}

			}
		}

		/// <returns> Returns the namingAuthorityId. </returns>
		public virtual ASN1ObjectIdentifier getNamingAuthorityId()
		{
			return namingAuthorityId;
		}

		/// <returns> Returns the namingAuthorityText. </returns>
		public virtual DirectoryString getNamingAuthorityText()
		{
			return namingAuthorityText;
		}

		/// <returns> Returns the namingAuthorityUrl. </returns>
		public virtual string getNamingAuthorityUrl()
		{
			return namingAuthorityUrl;
		}

		/// <summary>
		/// Constructor from given details.
		/// <para>
		/// All parameters can be combined.
		/// 
		/// </para>
		/// </summary>
		/// <param name="namingAuthorityId">   ObjectIdentifier for naming authority. </param>
		/// <param name="namingAuthorityUrl">  URL for naming authority. </param>
		/// <param name="namingAuthorityText"> Textual representation of naming authority. </param>
		public NamingAuthority(ASN1ObjectIdentifier namingAuthorityId, string namingAuthorityUrl, DirectoryString namingAuthorityText)
		{
			this.namingAuthorityId = namingAuthorityId;
			this.namingAuthorityUrl = namingAuthorityUrl;
			this.namingAuthorityText = namingAuthorityText;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///             NamingAuthority ::= SEQUENCE
		///             {
		///               namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
		///               namingAuthorityUrl IA5String OPTIONAL,
		///               namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		///             }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			if (namingAuthorityId != null)
			{
				vec.add(namingAuthorityId);
			}
			if (!string.ReferenceEquals(namingAuthorityUrl, null))
			{
				vec.add(new DERIA5String(namingAuthorityUrl, true));
			}
			if (namingAuthorityText != null)
			{
				vec.add(namingAuthorityText);
			}
			return new DERSequence(vec);
		}
	}

}