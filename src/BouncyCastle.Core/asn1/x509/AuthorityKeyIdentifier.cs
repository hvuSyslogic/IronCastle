using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;
using org.bouncycastle.crypto.digests;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.asn1.x509
{

			
	/// <summary>
	/// The AuthorityKeyIdentifier object.
	/// <pre>
	/// id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
	/// 
	///   AuthorityKeyIdentifier ::= SEQUENCE {
	///      keyIdentifier             [0] IMPLICIT KeyIdentifier           OPTIONAL,
	///      authorityCertIssuer       [1] IMPLICIT GeneralNames            OPTIONAL,
	///      authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL  }
	/// 
	///   KeyIdentifier ::= OCTET STRING
	/// </pre>
	/// 
	/// </summary>
	public class AuthorityKeyIdentifier : ASN1Object
	{
		internal ASN1OctetString keyidentifier = null;
		internal GeneralNames certissuer = null;
		internal ASN1Integer certserno = null;

		public static AuthorityKeyIdentifier getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static AuthorityKeyIdentifier getInstance(object obj)
		{
			if (obj is AuthorityKeyIdentifier)
			{
				return (AuthorityKeyIdentifier)obj;
			}
			if (obj != null)
			{
				return new AuthorityKeyIdentifier(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static AuthorityKeyIdentifier fromExtensions(Extensions extensions)
		{
			 return AuthorityKeyIdentifier.getInstance(extensions.getExtensionParsedValue(Extension.authorityKeyIdentifier));
		}

		public AuthorityKeyIdentifier(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1TaggedObject o = DERTaggedObject.getInstance(e.nextElement());

				switch (o.getTagNo())
				{
				case 0:
					this.keyidentifier = ASN1OctetString.getInstance(o, false);
					break;
				case 1:
					this.certissuer = GeneralNames.getInstance(o, false);
					break;
				case 2:
					this.certserno = ASN1Integer.getInstance(o, false);
					break;
				default:
					throw new IllegalArgumentException("illegal tag");
				}
			}
		}

		/// 
		/// <summary>
		/// Calulates the keyidentifier using a SHA1 hash over the BIT STRING
		/// from SubjectPublicKeyInfo as defined in RFC2459.
		/// 
		/// Example of making a AuthorityKeyIdentifier:
		/// <pre>
		///   SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
		///       publicKey.getEncoded()).readObject());
		///   AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
		/// </pre> </summary>
		/// @deprecated create the extension using org.bouncycastle.cert.X509ExtensionUtils
		///  
		public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki)
		{
			Digest digest = new SHA1Digest();
			byte[] resBuf = new byte[digest.getDigestSize()];

			byte[] bytes = spki.getPublicKeyData().getBytes();
			digest.update(bytes, 0, bytes.Length);
			digest.doFinal(resBuf, 0);
			this.keyidentifier = new DEROctetString(resBuf);
		}

		/// <summary>
		/// create an AuthorityKeyIdentifier with the GeneralNames tag and
		/// the serial number provided as well. </summary>
		/// @deprecated create the extension using org.bouncycastle.cert.X509ExtensionUtils 
		public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki, GeneralNames name, BigInteger serialNumber)
		{
			Digest digest = new SHA1Digest();
			byte[] resBuf = new byte[digest.getDigestSize()];

			byte[] bytes = spki.getPublicKeyData().getBytes();
			digest.update(bytes, 0, bytes.Length);
			digest.doFinal(resBuf, 0);

			this.keyidentifier = new DEROctetString(resBuf);
			this.certissuer = GeneralNames.getInstance(name.toASN1Primitive());
			this.certserno = new ASN1Integer(serialNumber);
		}

		/// <summary>
		/// create an AuthorityKeyIdentifier with the GeneralNames tag and
		/// the serial number provided.
		/// </summary>
		public AuthorityKeyIdentifier(GeneralNames name, BigInteger serialNumber) : this((byte[])null, name, serialNumber)
		{
		}

		/// <summary>
		/// create an AuthorityKeyIdentifier with a precomputed key identifier
		/// </summary>
		 public AuthorityKeyIdentifier(byte[] keyIdentifier) : this(keyIdentifier, null, null)
		 {
		 }

		/// <summary>
		/// create an AuthorityKeyIdentifier with a precomputed key identifier
		/// and the GeneralNames tag and the serial number provided as well.
		/// </summary>
		public AuthorityKeyIdentifier(byte[] keyIdentifier, GeneralNames name, BigInteger serialNumber)
		{
			this.keyidentifier = (keyIdentifier != null) ? new DEROctetString(keyIdentifier) : null;
			this.certissuer = name;
			this.certserno = (serialNumber != null) ? new ASN1Integer(serialNumber) : null;
		}

		public virtual byte[] getKeyIdentifier()
		{
			if (keyidentifier != null)
			{
				return keyidentifier.getOctets();
			}

			return null;
		}

		public virtual GeneralNames getAuthorityCertIssuer()
		{
			return certissuer;
		}

		public virtual BigInteger getAuthorityCertSerialNumber()
		{
			if (certserno != null)
			{
				return certserno.getValue();
			}

			return null;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (keyidentifier != null)
			{
				v.add(new DERTaggedObject(false, 0, keyidentifier));
			}

			if (certissuer != null)
			{
				v.add(new DERTaggedObject(false, 1, certissuer));
			}

			if (certserno != null)
			{
				v.add(new DERTaggedObject(false, 2, certserno));
			}


			return new DERSequence(v);
		}

		public override string ToString()
		{
			return ("AuthorityKeyIdentifier: KeyID(" + ((keyidentifier != null) ? Hex.toHexString(this.keyidentifier.getOctets()) : "null") + ")");
		}
	}

}