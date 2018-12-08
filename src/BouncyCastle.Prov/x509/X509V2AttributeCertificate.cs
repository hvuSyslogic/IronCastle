using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using AttributeCertificate = org.bouncycastle.asn1.x509.AttributeCertificate;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// An implementation of a version 2 X.509 Attribute Certificate. </summary>
	/// @deprecated use org.bouncycastle.cert.X509AttributeCertificateHolder 
	public class X509V2AttributeCertificate : X509AttributeCertificate
	{
		private AttributeCertificate cert;
		private DateTime notBefore;
		private DateTime notAfter;

		private static AttributeCertificate getObject(InputStream @in)
		{
			try
			{
				return AttributeCertificate.getInstance((new ASN1InputStream(@in)).readObject());
			}
			catch (IOException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new IOException("exception decoding certificate structure: " + e.ToString());
			}
		}

		public X509V2AttributeCertificate(InputStream encIn) : this(getObject(encIn))
		{
		}

		public X509V2AttributeCertificate(byte[] encoded) : this(new ByteArrayInputStream(encoded))
		{
		}

		public X509V2AttributeCertificate(AttributeCertificate cert)
		{
			this.cert = cert;

			try
			{
				this.notAfter = cert.getAcinfo().getAttrCertValidityPeriod().getNotAfterTime().getDate();
				this.notBefore = cert.getAcinfo().getAttrCertValidityPeriod().getNotBeforeTime().getDate();
			}
			catch (ParseException)
			{
				throw new IOException("invalid data structure in certificate!");
			}
		}

		public virtual int getVersion()
		{
			return cert.getAcinfo().getVersion().getValue().intValue() + 1;
		}

		public virtual BigInteger getSerialNumber()
		{
			return cert.getAcinfo().getSerialNumber().getValue();
		}

		public virtual AttributeCertificateHolder getHolder()
		{
			return new AttributeCertificateHolder((ASN1Sequence)cert.getAcinfo().getHolder().toASN1Primitive());
		}

		public virtual AttributeCertificateIssuer getIssuer()
		{
			return new AttributeCertificateIssuer(cert.getAcinfo().getIssuer());
		}

		public virtual DateTime getNotBefore()
		{
			return notBefore;
		}

		public virtual DateTime getNotAfter()
		{
			return notAfter;
		}

		public virtual bool[] getIssuerUniqueID()
		{
			DERBitString id = cert.getAcinfo().getIssuerUniqueID();

			if (id != null)
			{
				byte[] bytes = id.getBytes();
				bool[] boolId = new bool[bytes.Length * 8 - id.getPadBits()];

				for (int i = 0; i != boolId.Length; i++)
				{
					boolId[i] = (bytes[i / 8] & ((int)((uint)0x80 >> (i % 8)))) != 0;
				}

				return boolId;
			}

			return null;
		}

		public virtual void checkValidity()
		{
			this.checkValidity(DateTime.Now);
		}

		public virtual void checkValidity(DateTime date)
		{
			if (date > this.getNotAfter())
			{
				throw new CertificateExpiredException("certificate expired on " + this.getNotAfter());
			}

			if (date < this.getNotBefore())
			{
				throw new CertificateNotYetValidException("certificate not valid till " + this.getNotBefore());
			}
		}

		public virtual byte[] getSignature()
		{
			return cert.getSignatureValue().getOctets();
		}

		public void verify(PublicKey key, string provider)
		{
			Signature signature = null;

			if (!cert.getSignatureAlgorithm().Equals(cert.getAcinfo().getSignature()))
			{
				throw new CertificateException("Signature algorithm in certificate info not same as outer certificate");
			}

			signature = Signature.getInstance(cert.getSignatureAlgorithm().getAlgorithm().getId(), provider);

			signature.initVerify(key);

			try
			{
				signature.update(cert.getAcinfo().getEncoded());
			}
			catch (IOException)
			{
				throw new SignatureException("Exception encoding certificate info object");
			}

			if (!signature.verify(this.getSignature()))
			{
				throw new InvalidKeyException("Public key presented not for certificate signature");
			}
		}

		public virtual byte[] getEncoded()
		{
			return cert.getEncoded();
		}

		public virtual byte[] getExtensionValue(string oid)
		{
			Extensions extensions = cert.getAcinfo().getExtensions();

			if (extensions != null)
			{
				Extension ext = extensions.getExtension(new ASN1ObjectIdentifier(oid));

				if (ext != null)
				{
					try
					{
						return ext.getExtnValue().getEncoded(ASN1Encoding_Fields.DER);
					}
					catch (Exception e)
					{
						throw new RuntimeException("error encoding " + e.ToString());
					}
				}
			}

			return null;
		}

		private Set getExtensionOIDs(bool critical)
		{
			Extensions extensions = cert.getAcinfo().getExtensions();

			if (extensions != null)
			{
				Set set = new HashSet();
				Enumeration e = extensions.oids();

				while (e.hasMoreElements())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
					Extension ext = extensions.getExtension(oid);

					if (ext.isCritical() == critical)
					{
						set.add(oid.getId());
					}
				}

				return set;
			}

			return null;
		}

		public virtual Set getNonCriticalExtensionOIDs()
		{
			return getExtensionOIDs(false);
		}

		public virtual Set getCriticalExtensionOIDs()
		{
			return getExtensionOIDs(true);
		}

		public virtual bool hasUnsupportedCriticalExtension()
		{
			Set extensions = getCriticalExtensionOIDs();

			return extensions != null && !extensions.isEmpty();
		}

		public virtual X509Attribute[] getAttributes()
		{
			ASN1Sequence seq = cert.getAcinfo().getAttributes();
			X509Attribute[] attrs = new X509Attribute[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				attrs[i] = new X509Attribute((ASN1Encodable)seq.getObjectAt(i));
			}

			return attrs;
		}

		public virtual X509Attribute[] getAttributes(string oid)
		{
			ASN1Sequence seq = cert.getAcinfo().getAttributes();
			List list = new ArrayList();

			for (int i = 0; i != seq.size(); i++)
			{
				X509Attribute attr = new X509Attribute((ASN1Encodable)seq.getObjectAt(i));
				if (attr.getOID().Equals(oid))
				{
					list.add(attr);
				}
			}

			if (list.size() == 0)
			{
				return null;
			}

			return (X509Attribute[])list.toArray(new X509Attribute[list.size()]);
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is X509AttributeCertificate))
			{
				return false;
			}

			X509AttributeCertificate other = (X509AttributeCertificate)o;

			try
			{
				byte[] b1 = this.getEncoded();
				byte[] b2 = other.getEncoded();

				return Arrays.areEqual(b1, b2);
			}
			catch (IOException)
			{
				return false;
			}
		}

		public override int GetHashCode()
		{
			try
			{
				return Arrays.GetHashCode(this.getEncoded());
			}
			catch (IOException)
			{
				return 0;
			}
		}
	}

}