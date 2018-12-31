using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cms
{

	
	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-5.3">RFC 5652</a>:
	/// Signature container per Signer, see <seealso cref="SignerIdentifier"/>.
	/// <pre>
	/// PKCS#7:
	/// 
	/// SignerInfo ::= SEQUENCE {
	///     version                   Version,
	///     sid                       SignerIdentifier,
	///     digestAlgorithm           DigestAlgorithmIdentifier,
	///     authenticatedAttributes   [0] IMPLICIT Attributes OPTIONAL,
	///     digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
	///     encryptedDigest           EncryptedDigest,
	///     unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
	/// }
	/// 
	/// EncryptedDigest ::= OCTET STRING
	/// 
	/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
	/// 
	/// DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
	/// 
	/// -----------------------------------------
	/// 
	/// RFC 5652:
	/// 
	/// SignerInfo ::= SEQUENCE {
	///     version            CMSVersion,
	///     sid                SignerIdentifier,
	///     digestAlgorithm    DigestAlgorithmIdentifier,
	///     signedAttrs        [0] IMPLICIT SignedAttributes OPTIONAL,
	///     signatureAlgorithm SignatureAlgorithmIdentifier,
	///     signature          SignatureValue,
	///     unsignedAttrs      [1] IMPLICIT UnsignedAttributes OPTIONAL
	/// }
	/// 
	/// -- <seealso cref="SignerIdentifier"/> referenced certificates are at containing
	/// -- <seealso cref="SignedData"/> certificates element.
	/// 
	/// SignerIdentifier ::= CHOICE {
	///     issuerAndSerialNumber <seealso cref="IssuerAndSerialNumber"/>,
	///     subjectKeyIdentifier  [0] SubjectKeyIdentifier }
	/// 
	/// -- See <seealso cref="Attributes"/> for generalized SET OF <seealso cref="Attribute"/>
	/// 
	/// SignedAttributes   ::= SET SIZE (1..MAX) OF Attribute
	/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
	/// 
	/// <seealso cref="Attribute"/> ::= SEQUENCE {
	///     attrType   OBJECT IDENTIFIER,
	///     attrValues SET OF AttributeValue }
	/// 
	/// AttributeValue ::= ANY
	/// 
	/// SignatureValue ::= OCTET STRING
	/// </pre>
	/// </summary>
	public class SignerInfo : ASN1Object
	{
		private ASN1Integer version;
		private SignerIdentifier sid;
		private AlgorithmIdentifier digAlgorithm;
		private ASN1Set authenticatedAttributes;
		private AlgorithmIdentifier digEncryptionAlgorithm;
		private ASN1OctetString encryptedDigest;
		private ASN1Set unauthenticatedAttributes;

		/// <summary>
		/// Return a SignerInfo object from the given input
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="SignerInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with SignerInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static SignerInfo getInstance(object o)
		{
			if (o is SignerInfo)
			{
				return (SignerInfo)o;
			}
			else if (o != null)
			{
				return new SignerInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// 
		/// <param name="sid"> </param>
		/// <param name="digAlgorithm">            CMS knows as 'digestAlgorithm' </param>
		/// <param name="authenticatedAttributes"> CMS knows as 'signedAttrs' </param>
		/// <param name="digEncryptionAlgorithm">  CMS knows as 'signatureAlgorithm' </param>
		/// <param name="encryptedDigest">         CMS knows as 'signature' </param>
		/// <param name="unauthenticatedAttributes"> CMS knows as 'unsignedAttrs' </param>
		public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digAlgorithm, ASN1Set authenticatedAttributes, AlgorithmIdentifier digEncryptionAlgorithm, ASN1OctetString encryptedDigest, ASN1Set unauthenticatedAttributes)
		{
			if (sid.isTagged())
			{
				this.version = new ASN1Integer(3);
			}
			else
			{
				this.version = new ASN1Integer(1);
			}

			this.sid = sid;
			this.digAlgorithm = digAlgorithm;
			this.authenticatedAttributes = authenticatedAttributes;
			this.digEncryptionAlgorithm = digEncryptionAlgorithm;
			this.encryptedDigest = encryptedDigest;
			this.unauthenticatedAttributes = unauthenticatedAttributes;
		}

		/// 
		/// <param name="sid"> </param>
		/// <param name="digAlgorithm">            CMS knows as 'digestAlgorithm' </param>
		/// <param name="authenticatedAttributes"> CMS knows as 'signedAttrs' </param>
		/// <param name="digEncryptionAlgorithm">  CMS knows as 'signatureAlgorithm' </param>
		/// <param name="encryptedDigest">         CMS knows as 'signature' </param>
		/// <param name="unauthenticatedAttributes"> CMS knows as 'unsignedAttrs' </param>
		public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digAlgorithm, Attributes authenticatedAttributes, AlgorithmIdentifier digEncryptionAlgorithm, ASN1OctetString encryptedDigest, Attributes unauthenticatedAttributes)
		{
			if (sid.isTagged())
			{
				this.version = new ASN1Integer(3);
			}
			else
			{
				this.version = new ASN1Integer(1);
			}

			this.sid = sid;
			this.digAlgorithm = digAlgorithm;
			this.authenticatedAttributes = ASN1Set.getInstance(authenticatedAttributes);
			this.digEncryptionAlgorithm = digEncryptionAlgorithm;
			this.encryptedDigest = encryptedDigest;
			this.unauthenticatedAttributes = ASN1Set.getInstance(unauthenticatedAttributes);
		}

		/// @deprecated use getInstance() method. 
		public SignerInfo(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			version = (ASN1Integer)e.nextElement();
			sid = SignerIdentifier.getInstance(e.nextElement());
			digAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());

			object obj = e.nextElement();

			if (obj is ASN1TaggedObject)
			{
				authenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)obj, false);

				digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
			}
			else
			{
				authenticatedAttributes = null;
				digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(obj);
			}

			encryptedDigest = DEROctetString.getInstance(e.nextElement());

			if (e.hasMoreElements())
			{
				unauthenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)e.nextElement(), false);
			}
			else
			{
				unauthenticatedAttributes = null;
			}
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual SignerIdentifier getSID()
		{
			return sid;
		}

		public virtual ASN1Set getAuthenticatedAttributes()
		{
			return authenticatedAttributes;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			return digAlgorithm;
		}

		public virtual ASN1OctetString getEncryptedDigest()
		{
			return encryptedDigest;
		}

		public virtual AlgorithmIdentifier getDigestEncryptionAlgorithm()
		{
			return digEncryptionAlgorithm;
		}

		public virtual ASN1Set getUnauthenticatedAttributes()
		{
			return unauthenticatedAttributes;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(sid);
			v.add(digAlgorithm);

			if (authenticatedAttributes != null)
			{
				v.add(new DERTaggedObject(false, 0, authenticatedAttributes));
			}

			v.add(digEncryptionAlgorithm);
			v.add(encryptedDigest);

			if (unauthenticatedAttributes != null)
			{
				v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
			}

			return new DERSequence(v);
		}
	}

}