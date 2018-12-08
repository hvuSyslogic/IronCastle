using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Enumerated = org.bouncycastle.asn1.ASN1Enumerated;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Dump = org.bouncycastle.asn1.util.ASN1Dump;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using X509Extension = org.bouncycastle.asn1.x509.X509Extension;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// The following extensions are listed in RFC 2459 as relevant to CRL Entries
	/// 
	/// ReasonCode Hode Instruction Code Invalidity Date Certificate Issuer
	/// (critical)
	/// </summary>
	public class X509CRLEntryObject : X509CRLEntry
	{
		private TBSCertList.CRLEntry c;

		private X500Name certificateIssuer;
		private int hashValue;
		private bool isHashValueSet;

		public X509CRLEntryObject(TBSCertList.CRLEntry c)
		{
			this.c = c;
			this.certificateIssuer = null;
		}

		/// <summary>
		/// Constructor for CRLEntries of indirect CRLs. If <code>isIndirect</code>
		/// is <code>false</code> <seealso cref="#getCertificateIssuer()"/> will always
		/// return <code>null</code>, <code>previousCertificateIssuer</code> is
		/// ignored. If this <code>isIndirect</code> is specified and this CRLEntry
		/// has no certificate issuer CRL entry extension
		/// <code>previousCertificateIssuer</code> is returned by
		/// <seealso cref="#getCertificateIssuer()"/>.
		/// </summary>
		/// <param name="c">
		///            TBSCertList.CRLEntry object. </param>
		/// <param name="isIndirect">
		///            <code>true</code> if the corresponding CRL is a indirect
		///            CRL. </param>
		/// <param name="previousCertificateIssuer">
		///            Certificate issuer of the previous CRLEntry. </param>
		public X509CRLEntryObject(TBSCertList.CRLEntry c, bool isIndirect, X500Name previousCertificateIssuer)
		{
			this.c = c;
			this.certificateIssuer = loadCertificateIssuer(isIndirect, previousCertificateIssuer);
		}

		/// <summary>
		/// Will return true if any extensions are present and marked as critical as
		/// we currently don't handle any extensions!
		/// </summary>
		public virtual bool hasUnsupportedCriticalExtension()
		{
			Set extns = getCriticalExtensionOIDs();

			return extns != null && !extns.isEmpty();
		}

		private X500Name loadCertificateIssuer(bool isIndirect, X500Name previousCertificateIssuer)
		{
			if (!isIndirect)
			{
				return null;
			}

			Extension ext = getExtension(Extension.certificateIssuer);
			if (ext == null)
			{
				return previousCertificateIssuer;
			}

			try
			{
				GeneralName[] names = GeneralNames.getInstance(ext.getParsedValue()).getNames();
				for (int i = 0; i < names.Length; i++)
				{
					if (names[i].getTagNo() == GeneralName.directoryName)
					{
						return X500Name.getInstance(names[i].getName());
					}
				}
				return null;
			}
			catch (Exception)
			{
				return null;
			}
		}

		public virtual X500Principal getCertificateIssuer()
		{
			if (certificateIssuer == null)
			{
				return null;
			}
			try
			{
				return new X500Principal(certificateIssuer.getEncoded());
			}
			catch (IOException)
			{
				return null;
			}
		}

		private Set getExtensionOIDs(bool critical)
		{
			Extensions extensions = c.getExtensions();

			if (extensions != null)
			{
				Set set = new HashSet();
				Enumeration e = extensions.oids();

				while (e.hasMoreElements())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
					Extension ext = extensions.getExtension(oid);

					if (critical == ext.isCritical())
					{
						set.add(oid.getId());
					}
				}

				return set;
			}

			return null;
		}

		public virtual Set getCriticalExtensionOIDs()
		{
			return getExtensionOIDs(true);
		}

		public virtual Set getNonCriticalExtensionOIDs()
		{
			return getExtensionOIDs(false);
		}

		private Extension getExtension(ASN1ObjectIdentifier oid)
		{
			Extensions exts = c.getExtensions();

			if (exts != null)
			{
				return exts.getExtension(oid);
			}

			return null;
		}

		public virtual byte[] getExtensionValue(string oid)
		{
			Extension ext = getExtension(new ASN1ObjectIdentifier(oid));

			if (ext != null)
			{
				try
				{
					return ext.getExtnValue().getEncoded();
				}
				catch (Exception e)
				{
					throw new RuntimeException("error encoding " + e.ToString());
				}
			}

			return null;
		}

		/// <summary>
		/// Cache the hashCode value - calculating it with the standard method. </summary>
		/// <returns>  calculated hashCode. </returns>
		public override int GetHashCode()
		{
			if (!isHashValueSet)
			{
				hashValue = base.GetHashCode();
				isHashValueSet = true;
			}

			return hashValue;
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is X509CRLEntryObject)
			{
				X509CRLEntryObject other = (X509CRLEntryObject)o;

				return this.c.Equals(other.c);
			}

			return base.Equals(this);
		}

		public virtual byte[] getEncoded()
		{
			try
			{
				return c.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new CRLException(e.ToString());
			}
		}

		public virtual BigInteger getSerialNumber()
		{
			return c.getUserCertificate().getValue();
		}

		public virtual DateTime getRevocationDate()
		{
			return c.getRevocationDate().getDate();
		}

		public virtual bool hasExtensions()
		{
			return c.getExtensions() != null;
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("      userCertificate: ").append(this.getSerialNumber()).append(nl);
			buf.append("       revocationDate: ").append(this.getRevocationDate()).append(nl);
			buf.append("       certificateIssuer: ").append(this.getCertificateIssuer()).append(nl);

			Extensions extensions = c.getExtensions();

			if (extensions != null)
			{
				Enumeration e = extensions.oids();
				if (e.hasMoreElements())
				{
					buf.append("   crlEntryExtensions:").append(nl);

					while (e.hasMoreElements())
					{
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
						Extension ext = extensions.getExtension(oid);
						if (ext.getExtnValue() != null)
						{
							byte[] octs = ext.getExtnValue().getOctets();
							ASN1InputStream dIn = new ASN1InputStream(octs);
							buf.append("                       critical(").append(ext.isCritical()).append(") ");
							try
							{
								if (oid.Equals(X509Extension.reasonCode))
								{
									buf.append(CRLReason.getInstance(ASN1Enumerated.getInstance(dIn.readObject()))).append(nl);
								}
								else if (oid.Equals(X509Extension.certificateIssuer))
								{
									buf.append("Certificate issuer: ").append(GeneralNames.getInstance(dIn.readObject())).append(nl);
								}
								else
								{
									buf.append(oid.getId());
									buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
								}
							}
							catch (Exception)
							{
								buf.append(oid.getId());
								buf.append(" value = ").append("*****").append(nl);
							}
						}
						else
						{
							buf.append(nl);
						}
					}
				}
			}

			return buf.ToString();
		}
	}

}