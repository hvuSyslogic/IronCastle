namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AttCertIssuer = org.bouncycastle.asn1.x509.AttCertIssuer;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using V2Form = org.bouncycastle.asn1.x509.V2Form;
	using X509Principal = org.bouncycastle.jce.X509Principal;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// Carrying class for an attribute certificate issuer. </summary>
	/// @deprecated use org.bouncycastle.cert.AttributeCertificateIssuer 
	public class AttributeCertificateIssuer : CertSelector, Selector
	{
		internal readonly ASN1Encodable form;

		/// <summary>
		/// Set the issuer directly with the ASN.1 structure.
		/// </summary>
		/// <param name="issuer"> The issuer </param>
		public AttributeCertificateIssuer(AttCertIssuer issuer)
		{
			form = issuer.getIssuer();
		}

		public AttributeCertificateIssuer(X500Principal principal) : this(new X509Principal(principal.getEncoded()))
		{
		}

		public AttributeCertificateIssuer(X509Principal principal)
		{
			form = new V2Form(GeneralNames.getInstance(new DERSequence(new GeneralName(principal))));
		}

		private object[] getNames()
		{
			GeneralNames name;

			if (form is V2Form)
			{
				name = ((V2Form)form).getIssuerName();
			}
			else
			{
				name = (GeneralNames)form;
			}

			GeneralName[] names = name.getNames();

			List l = new ArrayList(names.Length);

			for (int i = 0; i != names.Length; i++)
			{
				if (names[i].getTagNo() == GeneralName.directoryName)
				{
					try
					{
						l.add(new X500Principal(((ASN1Encodable)names[i].getName()).toASN1Primitive().getEncoded()));
					}
					catch (IOException)
					{
						throw new RuntimeException("badly formed Name object");
					}
				}
			}

			return l.toArray(new object[l.size()]);
		}

		/// <summary>
		/// Return any principal objects inside the attribute certificate issuer
		/// object.
		/// </summary>
		/// <returns> an array of Principal objects (usually X500Principal) </returns>
		public virtual Principal[] getPrincipals()
		{
			object[] p = this.getNames();
			List l = new ArrayList();

			for (int i = 0; i != p.Length; i++)
			{
				if (p[i] is Principal)
				{
					l.add(p[i]);
				}
			}

			return (Principal[])l.toArray(new Principal[l.size()]);
		}

		private bool matchesDN(X500Principal subject, GeneralNames targets)
		{
			GeneralName[] names = targets.getNames();

			for (int i = 0; i != names.Length; i++)
			{
				GeneralName gn = names[i];

				if (gn.getTagNo() == GeneralName.directoryName)
				{
					try
					{
						if ((new X500Principal(((ASN1Encodable)gn.getName()).toASN1Primitive().getEncoded())).Equals(subject))
						{
							return true;
						}
					}
					catch (IOException)
					{
					}
				}
			}

			return false;
		}

		public virtual object clone()
		{
			return new AttributeCertificateIssuer(AttCertIssuer.getInstance(form));
		}

		public virtual bool match(Certificate cert)
		{
			if (!(cert is X509Certificate))
			{
				return false;
			}

			X509Certificate x509Cert = (X509Certificate)cert;

			if (form is V2Form)
			{
				V2Form issuer = (V2Form)form;
				if (issuer.getBaseCertificateID() != null)
				{
					return issuer.getBaseCertificateID().getSerial().getValue().Equals(x509Cert.getSerialNumber()) && matchesDN(x509Cert.getIssuerX500Principal(), issuer.getBaseCertificateID().getIssuer());
				}

				GeneralNames name = issuer.getIssuerName();
				if (matchesDN(x509Cert.getSubjectX500Principal(), name))
				{
					return true;
				}
			}
			else
			{
				GeneralNames name = (GeneralNames)form;
				if (matchesDN(x509Cert.getSubjectX500Principal(), name))
				{
					return true;
				}
			}

			return false;
		}

		public override bool Equals(object obj)
		{
			if (obj == this)
			{
				return true;
			}

			if (!(obj is AttributeCertificateIssuer))
			{
				return false;
			}

			AttributeCertificateIssuer other = (AttributeCertificateIssuer)obj;

			return this.form.Equals(other.form);
		}

		public override int GetHashCode()
		{
			return this.form.GetHashCode();
		}

		public virtual bool match(object obj)
		{
			if (!(obj is X509Certificate))
			{
				return false;
			}

			return match((Certificate)obj);
		}
	}

}