using System;

namespace org.bouncycastle.cert.selector
{

	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	/// <summary>
	/// This class builds selectors according to the set criteria.
	/// </summary>
	public class X509AttributeCertificateHolderSelectorBuilder
	{

		// TODO: name constraints???

		private AttributeCertificateHolder holder;

		private AttributeCertificateIssuer issuer;

		private BigInteger serialNumber;

		private DateTime attributeCertificateValid;

		private X509AttributeCertificateHolder attributeCert;

		private Collection targetNames = new HashSet();

		private Collection targetGroups = new HashSet();

		public X509AttributeCertificateHolderSelectorBuilder()
		{
		}

		/// <summary>
		/// Set the attribute certificate to be matched. If <code>null</code> is
		/// given any will do.
		/// </summary>
		/// <param name="attributeCert"> The attribute certificate holder to set. </param>
		public virtual void setAttributeCert(X509AttributeCertificateHolder attributeCert)
		{
			this.attributeCert = attributeCert;
		}

		/// <summary>
		/// Set the time, when the certificate must be valid. If <code>null</code>
		/// is given any will do.
		/// </summary>
		/// <param name="attributeCertificateValid"> The attribute certificate validation
		///            time to set. </param>
		public virtual void setAttributeCertificateValid(DateTime attributeCertificateValid)
		{
			if (attributeCertificateValid != null)
			{
				this.attributeCertificateValid = new DateTime(attributeCertificateValid.Ticks);
			}
			else
			{
				this.attributeCertificateValid = null;
			}
		}

		/// <summary>
		/// Sets the holder. If <code>null</code> is given any will do.
		/// </summary>
		/// <param name="holder"> The holder to set. </param>
		public virtual void setHolder(AttributeCertificateHolder holder)
		{
			this.holder = holder;
		}

		/// <summary>
		/// Sets the issuer the attribute certificate must have. If <code>null</code>
		/// is given any will do.
		/// </summary>
		/// <param name="issuer"> The issuer to set. </param>
		public virtual void setIssuer(AttributeCertificateIssuer issuer)
		{
			this.issuer = issuer;
		}

		/// <summary>
		/// Sets the serial number the attribute certificate must have. If
		/// <code>null</code> is given any will do.
		/// </summary>
		/// <param name="serialNumber"> The serialNumber to set. </param>
		public virtual void setSerialNumber(BigInteger serialNumber)
		{
			this.serialNumber = serialNumber;
		}

		/// <summary>
		/// Adds a target name criterion for the attribute certificate to the target
		/// information extension criteria. The <code>X509AttributeCertificateHolder</code>
		/// must contain at least one of the specified target names.
		/// <para>
		/// Each attribute certificate may contain a target information extension
		/// limiting the servers where this attribute certificate can be used. If
		/// this extension is not present, the attribute certificate is not targeted
		/// and may be accepted by any server.
		/// 
		/// </para>
		/// </summary>
		/// <param name="name"> The name as a GeneralName (not <code>null</code>) </param>
		public virtual void addTargetName(GeneralName name)
		{
			targetNames.add(name);
		}

		/// <summary>
		/// Adds a collection with target names criteria. If <code>null</code> is
		/// given any will do.
		/// <para>
		/// The collection consists of either GeneralName objects or byte[] arrays representing
		/// DER encoded GeneralName structures.
		/// 
		/// </para>
		/// </summary>
		/// <param name="names"> A collection of target names. </param>
		/// <exception cref="java.io.IOException"> if a parsing error occurs. </exception>
		/// <seealso cref= #addTargetName(org.bouncycastle.asn1.x509.GeneralName) </seealso>
		public virtual void setTargetNames(Collection names)
		{
			targetNames = extractGeneralNames(names);
		}

		/// <summary>
		/// Adds a target group criterion for the attribute certificate to the target
		/// information extension criteria. The <code>X509AttributeCertificateHolder</code>
		/// must contain at least one of the specified target groups.
		/// <para>
		/// Each attribute certificate may contain a target information extension
		/// limiting the servers where this attribute certificate can be used. If
		/// this extension is not present, the attribute certificate is not targeted
		/// and may be accepted by any server.
		/// 
		/// </para>
		/// </summary>
		/// <param name="group"> The group as GeneralName form (not <code>null</code>) </param>
		public virtual void addTargetGroup(GeneralName group)
		{
			targetGroups.add(group);
		}

		/// <summary>
		/// Adds a collection with target groups criteria. If <code>null</code> is
		/// given any will do.
		/// <para>
		/// The collection consists of <code>GeneralName</code> objects or <code>byte[]</code>
		/// representing DER encoded GeneralNames.
		/// 
		/// </para>
		/// </summary>
		/// <param name="names"> A collection of target groups. </param>
		/// <exception cref="java.io.IOException"> if a parsing error occurs. </exception>
		/// <seealso cref= #addTargetGroup(org.bouncycastle.asn1.x509.GeneralName) </seealso>
		public virtual void setTargetGroups(Collection names)
		{
			targetGroups = extractGeneralNames(names);
		}

		private Set extractGeneralNames(Collection names)
		{
			if (names == null || names.isEmpty())
			{
				return new HashSet();
			}
			Set temp = new HashSet();
			for (Iterator it = names.iterator(); it.hasNext();)
			{
				temp.add(GeneralName.getInstance(it.next()));
			}
			return temp;
		}

		public virtual X509AttributeCertificateHolderSelector build()
		{
			X509AttributeCertificateHolderSelector sel = new X509AttributeCertificateHolderSelector(holder, issuer, serialNumber, attributeCertificateValid, attributeCert, Collections.unmodifiableCollection(new HashSet(targetNames)), Collections.unmodifiableCollection(new HashSet(targetGroups)));

			return sel;
		}
	}

}