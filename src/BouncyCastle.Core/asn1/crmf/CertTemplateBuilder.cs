using org.bouncycastle.asn1.x500;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.crmf
{
					
	public class CertTemplateBuilder
	{
		private ASN1Integer version;
		private ASN1Integer serialNumber;
		private AlgorithmIdentifier signingAlg;
		private X500Name issuer;
		private OptionalValidity validity;
		private X500Name subject;
		private SubjectPublicKeyInfo publicKey;
		private DERBitString issuerUID;
		private DERBitString subjectUID;
		private Extensions extensions;

		/// <summary>
		/// Sets the X.509 version. Note: for X509v3, use 2 here. </summary>
		public virtual CertTemplateBuilder setVersion(int ver)
		{
			version = new ASN1Integer(ver);

			return this;
		}

		public virtual CertTemplateBuilder setSerialNumber(ASN1Integer ser)
		{
			serialNumber = ser;

			return this;
		}

		public virtual CertTemplateBuilder setSigningAlg(AlgorithmIdentifier aid)
		{
			signingAlg = aid;

			return this;
		}

		public virtual CertTemplateBuilder setIssuer(X500Name name)
		{
			issuer = name;

			return this;
		}

		public virtual CertTemplateBuilder setValidity(OptionalValidity v)
		{
			validity = v;

			return this;
		}

		public virtual CertTemplateBuilder setSubject(X500Name name)
		{
			subject = name;

			return this;
		}

		public virtual CertTemplateBuilder setPublicKey(SubjectPublicKeyInfo spki)
		{
			publicKey = spki;

			return this;
		}

		/// <summary>
		/// Sets the issuer unique ID (deprecated in X.509v3) </summary>
		public virtual CertTemplateBuilder setIssuerUID(DERBitString uid)
		{
			issuerUID = uid;

			return this;
		}

		/// <summary>
		/// Sets the subject unique ID (deprecated in X.509v3) </summary>
		public virtual CertTemplateBuilder setSubjectUID(DERBitString uid)
		{
			subjectUID = uid;

			return this;
		}

		/// @deprecated use method taking Extensions 
		public virtual CertTemplateBuilder setExtensions(X509Extensions extens)
		{
			return setExtensions(Extensions.getInstance(extens));
		}

		public virtual CertTemplateBuilder setExtensions(Extensions extens)
		{
			extensions = extens;

			return this;
		}

		/// <summary>
		/// <pre>
		///  CertTemplate ::= SEQUENCE {
		///      version      [0] Version               OPTIONAL,
		///      serialNumber [1] INTEGER               OPTIONAL,
		///      signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
		///      issuer       [3] Name                  OPTIONAL,
		///      validity     [4] OptionalValidity      OPTIONAL,
		///      subject      [5] Name                  OPTIONAL,
		///      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
		///      issuerUID    [7] UniqueIdentifier      OPTIONAL,
		///      subjectUID   [8] UniqueIdentifier      OPTIONAL,
		///      extensions   [9] Extensions            OPTIONAL }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public virtual CertTemplate build()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			addOptional(v, 0, false, version);
			addOptional(v, 1, false, serialNumber);
			addOptional(v, 2, false, signingAlg);
			addOptional(v, 3, true, issuer); // CHOICE
			addOptional(v, 4, false, validity);
			addOptional(v, 5, true, subject); // CHOICE
			addOptional(v, 6, false, publicKey);
			addOptional(v, 7, false, issuerUID);
			addOptional(v, 8, false, subjectUID);
			addOptional(v, 9, false, extensions);

			return CertTemplate.getInstance(new DERSequence(v));
		}

		private void addOptional(ASN1EncodableVector v, int tagNo, bool isExplicit, ASN1Encodable obj)
		{
			if (obj != null)
			{
				v.add(new DERTaggedObject(isExplicit, tagNo, obj));
			}
		}
	}

}