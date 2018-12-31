using System.IO;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmp
{

		
	public class CMPCertificate : ASN1Object, ASN1Choice
	{
		private Certificate x509v3PKCert;

		private int otherTagValue;
		private ASN1Object otherCert;

		/// <summary>
		/// Note: the addition of attribute certificates is a BC extension. If you use this constructor they
		/// will be added with a tag value of 1. </summary>
		/// @deprecated use (type. otherCert) constructor 
		public CMPCertificate(AttributeCertificate x509v2AttrCert) : this(1, x509v2AttrCert)
		{
		}

		/// <summary>
		/// Note: the addition of other certificates is a BC extension. If you use this constructor they
		/// will be added with an explicit tag value of type.
		/// </summary>
		/// <param name="type"> the type of the certificate (used as a tag value). </param>
		/// <param name="otherCert"> the object representing the certificate </param>
		public CMPCertificate(int type, ASN1Object otherCert)
		{
			this.otherTagValue = type;
			this.otherCert = otherCert;
		}

		public CMPCertificate(Certificate x509v3PKCert)
		{
			if (x509v3PKCert.getVersionNumber() != 3)
			{
				throw new IllegalArgumentException("only version 3 certificates allowed");
			}

			this.x509v3PKCert = x509v3PKCert;
		}

		public static CMPCertificate getInstance(object o)
		{
			if (o == null || o is CMPCertificate)
			{
				return (CMPCertificate)o;
			}

			if (o is byte[])
			{
				try
				{
					o = ASN1Primitive.fromByteArray((byte[])o);
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("Invalid encoding in CMPCertificate");
				}
			}

			if (o is ASN1Sequence)
			{
				return new CMPCertificate(Certificate.getInstance(o));
			}

			if (o is ASN1TaggedObject)
			{
				ASN1TaggedObject taggedObject = (ASN1TaggedObject)o;

				return new CMPCertificate(taggedObject.getTagNo(), taggedObject.getObject());
			}

			throw new IllegalArgumentException("Invalid object: " + o.GetType().getName());
		}

		public virtual bool isX509v3PKCert()
		{
			 return x509v3PKCert != null;
		}

		public virtual Certificate getX509v3PKCert()
		{
			return x509v3PKCert;
		}

		/// <summary>
		/// Return an AttributeCertificate interpretation of otherCert. </summary>
		/// @deprecated use getOtherCert and getOtherTag to make sure message is really what it should be.
		/// 
		/// <returns>  an AttributeCertificate </returns>
		public virtual AttributeCertificate getX509v2AttrCert()
		{
			return AttributeCertificate.getInstance(otherCert);
		}

		public virtual int getOtherCertTag()
		{
			return otherTagValue;
		}

		public virtual ASN1Object getOtherCert()
		{
			return otherCert;
		}

		/// <summary>
		/// <pre>
		/// CMPCertificate ::= CHOICE {
		///            x509v3PKCert    Certificate
		///            otherCert      [tag] EXPLICIT ANY DEFINED BY tag
		///  }
		/// </pre>
		/// Note: the addition of the explicit tagging is a BC extension. We apologise for the warped syntax, but hopefully you get the idea.
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			if (otherCert != null)
			{ // explicit following CMP conventions
				return new DERTaggedObject(true, otherTagValue, otherCert);
			}

			return x509v3PKCert.toASN1Primitive();
		}
	}

}