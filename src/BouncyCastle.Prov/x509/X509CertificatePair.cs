using org.bouncycastle.asn1;

namespace org.bouncycastle.x509
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificatePair = org.bouncycastle.asn1.x509.CertificatePair;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using X509CertificateObject = org.bouncycastle.jce.provider.X509CertificateObject;

	/// <summary>
	/// This class contains a cross certificate pair. Cross certificates pairs may
	/// contain two cross signed certificates from two CAs. A certificate from the
	/// other CA to this CA is contained in the forward certificate, the certificate
	/// from this CA to the other CA is contained in the reverse certificate.
	/// </summary>
	public class X509CertificatePair
	{
		private readonly JcaJceHelper bcHelper = new BCJcaJceHelper(); // needed to force provider loading

		private X509Certificate forward;
		private X509Certificate reverse;

		// TODO: should get rid of this class
		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="forward"> Certificate from the other CA to this CA. </param>
		/// <param name="reverse"> Certificate from this CA to the other CA. </param>
		public X509CertificatePair(X509Certificate forward, X509Certificate reverse)
		{
			this.forward = forward;
			this.reverse = reverse;
		}

		/// <summary>
		/// Constructor from a ASN.1 CertificatePair structure.
		/// </summary>
		/// <param name="pair"> The <code>CertificatePair</code> ASN.1 object. </param>
		public X509CertificatePair(CertificatePair pair)
		{
			if (pair.getForward() != null)
			{
				this.forward = new X509CertificateObject(pair.getForward());
			}
			if (pair.getReverse() != null)
			{
				this.reverse = new X509CertificateObject(pair.getReverse());
			}
		}

		public virtual byte[] getEncoded()
		{
			Certificate f = null;
			Certificate r = null;
			try
			{
				if (forward != null)
				{
					f = Certificate.getInstance((new ASN1InputStream(forward.getEncoded())).readObject());
					if (f == null)
					{
						throw new CertificateEncodingException("unable to get encoding for forward");
					}
				}
				if (reverse != null)
				{
					r = Certificate.getInstance((new ASN1InputStream(reverse.getEncoded())).readObject());
					if (r == null)
					{
						throw new CertificateEncodingException("unable to get encoding for reverse");
					}
				}
				return (new CertificatePair(f, r)).getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IllegalArgumentException e)
			{
				throw new ExtCertificateEncodingException(e.ToString(), e);
			}
			catch (IOException e)
			{
				throw new ExtCertificateEncodingException(e.ToString(), e);
			}
		}

		/// <summary>
		/// Returns the certificate from the other CA to this CA.
		/// </summary>
		/// <returns> Returns the forward certificate. </returns>
		public virtual X509Certificate getForward()
		{
			return forward;
		}

		/// <summary>
		/// Return the certificate from this CA to the other CA.
		/// </summary>
		/// <returns> Returns the reverse certificate. </returns>
		public virtual X509Certificate getReverse()
		{
			return reverse;
		}

		public override bool Equals(object o)
		{
			if (o == null)
			{
				return false;
			}
			if (!(o is X509CertificatePair))
			{
				return false;
			}
			X509CertificatePair pair = (X509CertificatePair)o;
			bool equalReverse = true;
			bool equalForward = true;
			if (forward != null)
			{
				equalForward = this.forward.Equals(pair.forward);
			}
			else
			{
				if (pair.forward != null)
				{
					equalForward = false;
				}
			}
			if (reverse != null)
			{
				equalReverse = this.reverse.Equals(pair.reverse);
			}
			else
			{
				if (pair.reverse != null)
				{
					equalReverse = false;
				}
			}
			return equalForward && equalReverse;
		}

		public override int GetHashCode()
		{
			int hash = -1;
			if (forward != null)
			{
				hash ^= forward.GetHashCode();
			}
			if (reverse != null)
			{
				hash *= 17;
				hash ^= reverse.GetHashCode();
			}
			return hash;
		}
	}

}