namespace org.bouncycastle.cert
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AttCertIssuer = org.bouncycastle.asn1.x509.AttCertIssuer;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using V2Form = org.bouncycastle.asn1.x509.V2Form;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// Carrying class for an attribute certificate issuer.
	/// </summary>
	public class AttributeCertificateIssuer : Selector
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

		public AttributeCertificateIssuer(X500Name principal)
		{
			form = new V2Form(new GeneralNames(new GeneralName(principal)));
		}

		public virtual X500Name[] getNames()
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
					l.add(X500Name.getInstance(names[i].getName()));
				}
			}

			return (X500Name[])l.toArray(new X500Name[l.size()]);
		}

		private bool matchesDN(X500Name subject, GeneralNames targets)
		{
			GeneralName[] names = targets.getNames();

			for (int i = 0; i != names.Length; i++)
			{
				GeneralName gn = names[i];

				if (gn.getTagNo() == GeneralName.directoryName)
				{
					if (X500Name.getInstance(gn.getName()).Equals(subject))
					{
						return true;
					}
				}
			}

			return false;
		}

		public virtual object clone()
		{
			return new AttributeCertificateIssuer(AttCertIssuer.getInstance(form));
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
			if (!(obj is X509CertificateHolder))
			{
				return false;
			}

			X509CertificateHolder x509Cert = (X509CertificateHolder)obj;

			if (form is V2Form)
			{
				V2Form issuer = (V2Form)form;
				if (issuer.getBaseCertificateID() != null)
				{
					return issuer.getBaseCertificateID().getSerial().getValue().Equals(x509Cert.getSerialNumber()) && matchesDN(x509Cert.getIssuer(), issuer.getBaseCertificateID().getIssuer());
				}

				GeneralNames name = issuer.getIssuerName();
				if (matchesDN(x509Cert.getSubject(), name))
				{
					return true;
				}
			}
			else
			{
				GeneralNames name = (GeneralNames)form;
				if (matchesDN(x509Cert.getSubject(), name))
				{
					return true;
				}
			}

			return false;
		}
	}

}