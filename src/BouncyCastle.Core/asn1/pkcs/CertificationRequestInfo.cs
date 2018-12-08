using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.pkcs
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;

	/// <summary>
	/// PKCS10 CertificationRequestInfo object.
	/// <pre>
	///  CertificationRequestInfo ::= SEQUENCE {
	///   version             INTEGER { v1(0) } (v1,...),
	///   subject             Name,
	///   subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
	///   attributes          [0] Attributes{{ CRIAttributes }}
	///  }
	/// 
	///  Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
	/// 
	///  Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
	///    type    ATTRIBUTE.&amp;id({IOSet}),
	///    values  SET SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
	///  }
	/// </pre>
	/// </summary>
	public class CertificationRequestInfo : ASN1Object
	{
		internal ASN1Integer version = new ASN1Integer(0);
		internal X500Name subject;
		internal SubjectPublicKeyInfo subjectPKInfo;
		internal ASN1Set attributes = null;

		public static CertificationRequestInfo getInstance(object obj)
		{
			if (obj is CertificationRequestInfo)
			{
				return (CertificationRequestInfo)obj;
			}
			else if (obj != null)
			{
				return new CertificationRequestInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Basic constructor.
		/// <para>
		/// Note: Early on a lot of CAs would only accept messages with attributes missing. As the ASN.1 def shows
		/// the attributes field is not optional so should always at least contain an empty set. If a fully compliant
		/// request is required, pass in an empty set, the class will otherwise interpret a null as it should
		/// encode the request with the field missing.
		/// </para>
		/// </summary>
		/// <param name="subject"> subject to be associated with the public key </param>
		/// <param name="pkInfo"> public key to be associated with subject </param>
		/// <param name="attributes"> any attributes to be associated with the request. </param>
		public CertificationRequestInfo(X500Name subject, SubjectPublicKeyInfo pkInfo, ASN1Set attributes)
		{
			if ((subject == null) || (pkInfo == null))
			{
				throw new IllegalArgumentException("Not all mandatory fields set in CertificationRequestInfo generator.");
			}

			validateAttributes(attributes);

			this.subject = subject;
			this.subjectPKInfo = pkInfo;
			this.attributes = attributes;
		}

		/// @deprecated use X500Name method. 
		public CertificationRequestInfo(X509Name subject, SubjectPublicKeyInfo pkInfo, ASN1Set attributes) : this(X500Name.getInstance(subject.toASN1Primitive()), pkInfo, attributes)
		{
		}

		/// @deprecated use getInstance(). 
		public CertificationRequestInfo(ASN1Sequence seq)
		{
			version = (ASN1Integer)seq.getObjectAt(0);

			subject = X500Name.getInstance(seq.getObjectAt(1));
			subjectPKInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(2));

			//
			// some CertificationRequestInfo objects seem to treat this field
			// as optional.
			//
			if (seq.size() > 3)
			{
				ASN1TaggedObject tagobj = (ASN1TaggedObject)seq.getObjectAt(3);
				attributes = ASN1Set.getInstance(tagobj, false);
			}

			validateAttributes(attributes);

			if ((subject == null) || (version == null) || (subjectPKInfo == null))
			{
				throw new IllegalArgumentException("Not all mandatory fields set in CertificationRequestInfo generator.");
			}
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual X500Name getSubject()
		{
			return subject;
		}

		public virtual SubjectPublicKeyInfo getSubjectPublicKeyInfo()
		{
			return subjectPKInfo;
		}

		public virtual ASN1Set getAttributes()
		{
			return attributes;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(subject);
			v.add(subjectPKInfo);

			if (attributes != null)
			{
				v.add(new DERTaggedObject(false, 0, attributes));
			}

			return new DERSequence(v);
		}

		private static void validateAttributes(ASN1Set attributes)
		{
			if (attributes == null)
			{
				return;
			}

			for (Enumeration en = attributes.getObjects(); en.hasMoreElements();)
			{
				Attribute attr = Attribute.getInstance(en.nextElement());
				if (attr.getAttrType().Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_challengePassword))
				{
					if (attr.getAttrValues().size() != 1)
					{
						throw new IllegalArgumentException("challengePassword attribute must have one value");
					}
				}
			}
		}
	}

}