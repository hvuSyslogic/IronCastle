using System;

namespace org.bouncycastle.voms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using Attribute = org.bouncycastle.asn1.x509.Attribute;
	using IetfAttrSyntax = org.bouncycastle.asn1.x509.IetfAttrSyntax;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;

	/// <summary>
	/// Representation of the authorization information (VO, server address
	/// and list of Fully Qualified Attribute Names, or FQANs) contained in
	/// a VOMS attribute certificate.
	/// </summary>
	public class VOMSAttribute
	{

		/// <summary>
		/// The ASN.1 object identifier for VOMS attributes
		/// </summary>
		public const string VOMS_ATTR_OID = "1.3.6.1.4.1.8005.100.100.4";
		private X509AttributeCertificateHolder myAC;
		private string myHostPort;
		private string myVo;
		private List myStringList = new ArrayList();
		private List myFQANs = new ArrayList();

		/// <summary>
		/// Parses the contents of an attribute certificate.<br>
		/// <b>NOTE:</b> Cryptographic signatures, time stamps etc. will <b>not</b> be checked.
		/// </summary>
		/// <param name="ac"> the attribute certificate to parse for VOMS attributes </param>
		public VOMSAttribute(X509AttributeCertificateHolder ac)
		{
			if (ac == null)
			{
				throw new IllegalArgumentException("VOMSAttribute: AttributeCertificate is NULL");
			}

			myAC = ac;

			Attribute[] l = ac.getAttributes(new ASN1ObjectIdentifier(VOMS_ATTR_OID));

			if (l == null)
			{
				return;
			}

			try
			{
				for (int i = 0; i != l.Length; i++)
				{
					IetfAttrSyntax attr = IetfAttrSyntax.getInstance(l[i].getAttributeValues()[0]);

					// policyAuthority is on the format <vo>/<host>:<port>
					string url = ((DERIA5String)attr.getPolicyAuthority().getNames()[0].getName()).getString();
					int idx = url.IndexOf("://", StringComparison.Ordinal);

					if ((idx < 0) || (idx == (url.Length - 1)))
					{
						throw new IllegalArgumentException("Bad encoding of VOMS policyAuthority : [" + url + "]");
					}

					myVo = url.Substring(0, idx);
					myHostPort = url.Substring(idx + 3);

					if (attr.getValueType() != IetfAttrSyntax.VALUE_OCTETS)
					{
						throw new IllegalArgumentException("VOMS attribute values are not encoded as octet strings, policyAuthority = " + url);
					}

					ASN1OctetString[] values = (ASN1OctetString[])attr.getValues();
					for (int j = 0; j != values.Length; j++)
					{
						string fqan = StringHelper.NewString(values[j].getOctets());
						FQAN f = new FQAN(this, fqan);

						if (!myStringList.contains(fqan) && fqan.StartsWith("/" + myVo + "/", StringComparison.Ordinal))
						{
							myStringList.add(fqan);
							myFQANs.add(f);
						}
					}
				}
			}
			catch (IllegalArgumentException ie)
			{
				throw ie;
			}
			catch (Exception)
			{
				throw new IllegalArgumentException("Badly encoded VOMS extension in AC issued by " + ac.getIssuer());
			}
		}

		/// <returns> The AttributeCertificate containing the VOMS information </returns>
		public virtual X509AttributeCertificateHolder getAC()
		{
			return myAC;
		}

		/// <returns> List of String of the VOMS fully qualified
		/// attributes names (FQANs):<br>
		/// <code>/vo[/group[/group2...]][/Role=[role]][/Capability=capability]</code> </returns>
		public virtual List getFullyQualifiedAttributes()
		{
			return myStringList;
		}

		/// <returns> List of FQAN of the VOMS fully qualified
		/// attributes names (FQANs) </returns>
		public virtual List getListOfFQAN()
		{
			return myFQANs;
		}

		/// <summary>
		/// Returns the address of the issuing VOMS server, on the form <code>&lt;host&gt;:&lt;port&gt;</code> </summary>
		/// <returns> String </returns>
		public virtual string getHostPort()
		{
			return myHostPort;
		}

		/// <summary>
		/// Returns the VO name
		/// @return
		/// </summary>
		public virtual string getVO()
		{
			return myVo;
		}

		public override string ToString()
		{
			return "VO      :" + myVo + "\n" + "HostPort:" + myHostPort + "\n" + "FQANs   :" + myFQANs;
		}

		/// <summary>
		/// Inner class providing a container of the group,role,capability
		/// information triplet in an FQAN.
		/// </summary>
		public class FQAN
		{
			private readonly VOMSAttribute outerInstance;

			internal string fqan;
			internal string group;
			internal string role;
			internal string capability;

			public FQAN(VOMSAttribute outerInstance, string fqan)
			{
				this.outerInstance = outerInstance;
				this.fqan = fqan;
			}

			public FQAN(VOMSAttribute outerInstance, string group, string role, string capability)
			{
				this.outerInstance = outerInstance;
				this.group = group;
				this.role = role;
				this.capability = capability;
			}

			public virtual string getFQAN()
			{
				if (!string.ReferenceEquals(fqan, null))
				{
					return fqan;
				}

				fqan = group + "/Role=" + ((!string.ReferenceEquals(role, null)) ? role : "") + ((!string.ReferenceEquals(capability, null)) ? ("/Capability=" + capability) : "");

				return fqan;
			}

			public virtual void split()
			{
				int len = fqan.Length;
				int i = fqan.IndexOf("/Role=", StringComparison.Ordinal);

				if (i < 0)
				{
					return;
				}

				group = fqan.Substring(0, i);

				int j = fqan.IndexOf("/Capability=", i + 6, StringComparison.Ordinal);
				string s = (j < 0) ? fqan.Substring(i + 6) : fqan.Substring(i + 6, j - (i + 6));
				role = (s.Length == 0) ? null : s;
				s = (j < 0) ? null : fqan.Substring(j + 12);
				capability = ((string.ReferenceEquals(s, null)) || (s.Length == 0)) ? null : s;
			}

			public virtual string getGroup()
			{
				if ((string.ReferenceEquals(group, null)) && (!string.ReferenceEquals(fqan, null)))
				{
					split();
				}

				return group;
			}

			public virtual string getRole()
			{
				if ((string.ReferenceEquals(group, null)) && (!string.ReferenceEquals(fqan, null)))
				{
					split();
				}

				return role;
			}

			public virtual string getCapability()
			{
				if ((string.ReferenceEquals(group, null)) && (!string.ReferenceEquals(fqan, null)))
				{
					split();
				}

				return capability;
			}

			public override string ToString()
			{
				return getFQAN();
			}
		}
	}

}