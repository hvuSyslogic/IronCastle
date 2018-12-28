using System;
using System.IO;
using BouncyCastle.Core.Port.java.lang;
using BouncyCastle.Core.Port.java.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class PKIXNameConstraintValidator : NameConstraintValidator
	{
		private Set excludedSubtreesDN = new HashSet();

		private Set excludedSubtreesDNS = new HashSet();

		private Set excludedSubtreesEmail = new HashSet();

		private Set excludedSubtreesURI = new HashSet();

		private Set excludedSubtreesIP = new HashSet();

		private Set excludedSubtreesOtherName = new HashSet();

		private Set permittedSubtreesDN;

		private Set permittedSubtreesDNS;

		private Set permittedSubtreesEmail;

		private Set permittedSubtreesURI;

		private Set permittedSubtreesIP;

		private Set permittedSubtreesOtherName;

		public PKIXNameConstraintValidator()
		{
		}

		/// <summary>
		/// Checks if the given GeneralName is in the permitted set.
		/// </summary>
		/// <param name="name"> The GeneralName </param>
		/// <exception cref="NameConstraintValidatorException"> If the <code>name</code> </exception>
		public virtual void checkPermitted(GeneralName name)
		{
			switch (name.getTagNo())
			{
			case GeneralName.otherName:
				checkPermittedOtherName(permittedSubtreesOtherName, OtherName.getInstance(name.getName()));
				break;
			case GeneralName.rfc822Name:
				checkPermittedEmail(permittedSubtreesEmail, extractNameAsString(name));
				break;
			case GeneralName.dNSName:
				checkPermittedDNS(permittedSubtreesDNS, DERIA5String.getInstance(name.getName()).getString());
				break;
			case GeneralName.directoryName:
				checkPermittedDN(X500Name.getInstance(name.getName()));
				break;
			case GeneralName.uniformResourceIdentifier:
				checkPermittedURI(permittedSubtreesURI, DERIA5String.getInstance(name.getName()).getString());
				break;
			case GeneralName.iPAddress:
				byte[] ip = ASN1OctetString.getInstance(name.getName()).getOctets();

				checkPermittedIP(permittedSubtreesIP, ip);
				break;
			default:
				throw new IllegalStateException("Unknown tag encountered: " + name.getTagNo());
			}
		}

		/// <summary>
		/// Check if the given GeneralName is contained in the excluded set.
		/// </summary>
		/// <param name="name"> The GeneralName. </param>
		/// <exception cref="NameConstraintValidatorException"> If the <code>name</code> is
		/// excluded. </exception>
		public virtual void checkExcluded(GeneralName name)
		{
			switch (name.getTagNo())
			{
			case GeneralName.otherName:
				checkExcludedOtherName(excludedSubtreesOtherName, OtherName.getInstance(name.getName()));
				break;
			case GeneralName.rfc822Name:
				checkExcludedEmail(excludedSubtreesEmail, extractNameAsString(name));
				break;
			case GeneralName.dNSName:
				checkExcludedDNS(excludedSubtreesDNS, DERIA5String.getInstance(name.getName()).getString());
				break;
			case GeneralName.directoryName:
				checkExcludedDN(X500Name.getInstance(name.getName()));
				break;
			case GeneralName.uniformResourceIdentifier:
				checkExcludedURI(excludedSubtreesURI, DERIA5String.getInstance(name.getName()).getString());
				break;
			case GeneralName.iPAddress:
				byte[] ip = ASN1OctetString.getInstance(name.getName()).getOctets();

				checkExcludedIP(excludedSubtreesIP, ip);
				break;
			default:
				throw new IllegalStateException("Unknown tag encountered: " + name.getTagNo());
			}
		}

		public virtual void intersectPermittedSubtree(GeneralSubtree permitted)
		{
			intersectPermittedSubtree(new GeneralSubtree[]{permitted});
		}

		/// <summary>
		/// Updates the permitted set of these name constraints with the intersection
		/// with the given subtree.
		/// </summary>
		/// <param name="permitted"> The permitted subtrees </param>
		public virtual void intersectPermittedSubtree(GeneralSubtree[] permitted)
		{
			Map subtreesMap = new HashMap();

			// group in sets in a map ordered by tag no.
			for (int i = 0; i != permitted.Length; i++)
			{
				GeneralSubtree subtree = permitted[i];
				int? tagNo = Integers.valueOf(subtree.getBase().getTagNo());
				if (subtreesMap.get(tagNo) == null)
				{
					subtreesMap.put(tagNo, new HashSet());
				}
				((Set)subtreesMap.get(tagNo)).add(subtree);
			}

			for (Iterator it = subtreesMap.entrySet().iterator(); it.hasNext();)
			{
				MapEntry entry = (MapEntry)it.next();

				// go through all subtree groups
				int nameType = ((int?)entry.getKey()).Value;
				switch (nameType)
				{
				case GeneralName.otherName:
					permittedSubtreesOtherName = intersectOtherName(permittedSubtreesOtherName, (Set)entry.getValue());
					break;
				case GeneralName.rfc822Name:
					permittedSubtreesEmail = intersectEmail(permittedSubtreesEmail, (Set)entry.getValue());
					break;
				case GeneralName.dNSName:
					permittedSubtreesDNS = intersectDNS(permittedSubtreesDNS, (Set)entry.getValue());
					break;
				case GeneralName.directoryName:
					permittedSubtreesDN = intersectDN(permittedSubtreesDN, (Set)entry.getValue());
					break;
				case GeneralName.uniformResourceIdentifier:
					permittedSubtreesURI = intersectURI(permittedSubtreesURI, (Set)entry.getValue());
					break;
				case GeneralName.iPAddress:
					permittedSubtreesIP = intersectIP(permittedSubtreesIP, (Set)entry.getValue());
					break;
				default:
					throw new IllegalStateException("Unknown tag encountered: " + nameType);
				}
			}
		}

		public virtual void intersectEmptyPermittedSubtree(int nameType)
		{
			switch (nameType)
			{
			case GeneralName.otherName:
				permittedSubtreesOtherName = new HashSet();
				break;
			case GeneralName.rfc822Name:
				permittedSubtreesEmail = new HashSet();
				break;
			case GeneralName.dNSName:
				permittedSubtreesDNS = new HashSet();
				break;
			case GeneralName.directoryName:
				permittedSubtreesDN = new HashSet();
				break;
			case GeneralName.uniformResourceIdentifier:
				permittedSubtreesURI = new HashSet();
				break;
			case GeneralName.iPAddress:
				permittedSubtreesIP = new HashSet();
				break;
			default:
				throw new IllegalStateException("Unknown tag encountered: " + nameType);
			}
		}

		/// <summary>
		/// Adds a subtree to the excluded set of these name constraints.
		/// </summary>
		/// <param name="subtree"> A subtree with an excluded GeneralName. </param>
		public virtual void addExcludedSubtree(GeneralSubtree subtree)
		{
			GeneralName @base = subtree.getBase();

			switch (@base.getTagNo())
			{
			case GeneralName.otherName:
				excludedSubtreesOtherName = unionOtherName(excludedSubtreesOtherName, OtherName.getInstance(@base.getName()));
				break;
			case GeneralName.rfc822Name:
				excludedSubtreesEmail = unionEmail(excludedSubtreesEmail, extractNameAsString(@base));
				break;
			case GeneralName.dNSName:
				excludedSubtreesDNS = unionDNS(excludedSubtreesDNS, extractNameAsString(@base));
				break;
			case GeneralName.directoryName:
				excludedSubtreesDN = unionDN(excludedSubtreesDN, (ASN1Sequence)@base.getName().toASN1Primitive());
				break;
			case GeneralName.uniformResourceIdentifier:
				excludedSubtreesURI = unionURI(excludedSubtreesURI, extractNameAsString(@base));
				break;
			case GeneralName.iPAddress:
				excludedSubtreesIP = unionIP(excludedSubtreesIP, ASN1OctetString.getInstance(@base.getName()).getOctets());
				break;
			default:
				throw new IllegalStateException("Unknown tag encountered: " + @base.getTagNo());
			}
		}

		public override int GetHashCode()
		{
			return hashCollection(excludedSubtreesDN) + hashCollection(excludedSubtreesDNS) + hashCollection(excludedSubtreesEmail) + hashCollection(excludedSubtreesIP) + hashCollection(excludedSubtreesURI) + hashCollection(excludedSubtreesOtherName) + hashCollection(permittedSubtreesDN) + hashCollection(permittedSubtreesDNS) + hashCollection(permittedSubtreesEmail) + hashCollection(permittedSubtreesIP) + hashCollection(permittedSubtreesURI) + hashCollection(permittedSubtreesOtherName);
		}

		public override bool Equals(object o)
		{
			if (!(o is PKIXNameConstraintValidator))
			{
				return false;
			}
			PKIXNameConstraintValidator constraintValidator = (PKIXNameConstraintValidator)o;
			return collectionsAreEqual(constraintValidator.excludedSubtreesDN, excludedSubtreesDN) && collectionsAreEqual(constraintValidator.excludedSubtreesDNS, excludedSubtreesDNS) && collectionsAreEqual(constraintValidator.excludedSubtreesEmail, excludedSubtreesEmail) && collectionsAreEqual(constraintValidator.excludedSubtreesIP, excludedSubtreesIP) && collectionsAreEqual(constraintValidator.excludedSubtreesURI, excludedSubtreesURI) && collectionsAreEqual(constraintValidator.excludedSubtreesOtherName, excludedSubtreesOtherName) && collectionsAreEqual(constraintValidator.permittedSubtreesDN, permittedSubtreesDN) && collectionsAreEqual(constraintValidator.permittedSubtreesDNS, permittedSubtreesDNS) && collectionsAreEqual(constraintValidator.permittedSubtreesEmail, permittedSubtreesEmail) && collectionsAreEqual(constraintValidator.permittedSubtreesIP, permittedSubtreesIP) && collectionsAreEqual(constraintValidator.permittedSubtreesURI, permittedSubtreesURI) && collectionsAreEqual(constraintValidator.permittedSubtreesOtherName, permittedSubtreesOtherName);
		}

		public override string ToString()
		{
			string temp = "";
			temp += "permitted:\n";
			if (permittedSubtreesDN != null)
			{
				temp += "DN:\n";
				temp += permittedSubtreesDN.ToString() + "\n";
			}
			if (permittedSubtreesDNS != null)
			{
				temp += "DNS:\n";
				temp += permittedSubtreesDNS.ToString() + "\n";
			}
			if (permittedSubtreesEmail != null)
			{
				temp += "Email:\n";
				temp += permittedSubtreesEmail.ToString() + "\n";
			}
			if (permittedSubtreesURI != null)
			{
				temp += "URI:\n";
				temp += permittedSubtreesURI.ToString() + "\n";
			}
			if (permittedSubtreesIP != null)
			{
				temp += "IP:\n";
				temp += stringifyIPCollection(permittedSubtreesIP) + "\n";
			}
			if (permittedSubtreesOtherName != null)
			{
				temp += "OtherName:\n";
				temp += stringifyOtherNameCollection(permittedSubtreesOtherName) + "\n";
			}
			temp += "excluded:\n";
			if (!excludedSubtreesDN.isEmpty())
			{
				temp += "DN:\n";
				temp += excludedSubtreesDN.ToString() + "\n";
			}
			if (!excludedSubtreesDNS.isEmpty())
			{
				temp += "DNS:\n";
				temp += excludedSubtreesDNS.ToString() + "\n";
			}
			if (!excludedSubtreesEmail.isEmpty())
			{
				temp += "Email:\n";
				temp += excludedSubtreesEmail.ToString() + "\n";
			}
			if (!excludedSubtreesURI.isEmpty())
			{
				temp += "URI:\n";
				temp += excludedSubtreesURI.ToString() + "\n";
			}
			if (!excludedSubtreesIP.isEmpty())
			{
				temp += "IP:\n";
				temp += stringifyIPCollection(excludedSubtreesIP) + "\n";
			}
			if (!excludedSubtreesOtherName.isEmpty())
			{
				temp += "OtherName:\n";
				temp += stringifyOtherNameCollection(excludedSubtreesOtherName) + "\n";
			}
			return temp;
		}

		private void checkPermittedDN(X500Name dns)
		{
			checkPermittedDN(permittedSubtreesDN, ASN1Sequence.getInstance(dns.toASN1Primitive()));
		}

		private void checkExcludedDN(X500Name dns)
		{
			checkExcludedDN(excludedSubtreesDN, ASN1Sequence.getInstance(dns));
		}

		private static bool withinDNSubtree(ASN1Sequence dns, ASN1Sequence subtree)
		{
			if (subtree.size() < 1)
			{
				return false;
			}

			if (subtree.size() > dns.size())
			{
				return false;
			}

			for (int j = subtree.size() - 1; j >= 0; j--)
			{
				if (!subtree.getObjectAt(j).Equals(dns.getObjectAt(j)))
				{
					return false;
				}
			}

			return true;
		}

		private void checkPermittedDN(Set permitted, ASN1Sequence dns)
		{
			if (permitted == null)
			{
				return;
			}

			if (permitted.isEmpty() && dns.size() == 0)
			{
				return;
			}
			Iterator it = permitted.iterator();

			while (it.hasNext())
			{
				ASN1Sequence subtree = (ASN1Sequence)it.next();

				if (withinDNSubtree(dns, subtree))
				{
					return;
				}
			}

			throw new NameConstraintValidatorException("Subject distinguished name is not from a permitted subtree");
		}

		private void checkExcludedDN(Set excluded, ASN1Sequence dns)
		{
			if (excluded.isEmpty())
			{
				return;
			}

			Iterator it = excluded.iterator();

			while (it.hasNext())
			{
				ASN1Sequence subtree = (ASN1Sequence)it.next();

				if (withinDNSubtree(dns, subtree))
				{
					throw new NameConstraintValidatorException("Subject distinguished name is from an excluded subtree");
				}
			}
		}

		private Set intersectDN(Set permitted, Set dns)
		{
			Set intersect = new HashSet();
			for (Iterator it = dns.iterator(); it.hasNext();)
			{
				ASN1Sequence dn = ASN1Sequence.getInstance(((GeneralSubtree)it.next()).getBase().getName().toASN1Primitive());
				if (permitted == null)
				{
					if (dn != null)
					{
						intersect.add(dn);
					}
				}
				else
				{
					Iterator _iter = permitted.iterator();
					while (_iter.hasNext())
					{
						ASN1Sequence subtree = (ASN1Sequence)_iter.next();

						if (withinDNSubtree(dn, subtree))
						{
							intersect.add(dn);
						}
						else if (withinDNSubtree(subtree, dn))
						{
							intersect.add(subtree);
						}
					}
				}
			}
			return intersect;
		}

		private Set unionDN(Set excluded, ASN1Sequence dn)
		{
			if (excluded.isEmpty())
			{
				if (dn == null)
				{
					return excluded;
				}
				excluded.add(dn);

				return excluded;
			}
			else
			{
				Set intersect = new HashSet();

				Iterator it = excluded.iterator();
				while (it.hasNext())
				{
					ASN1Sequence subtree = (ASN1Sequence)it.next();

					if (withinDNSubtree(dn, subtree))
					{
						intersect.add(subtree);
					}
					else if (withinDNSubtree(subtree, dn))
					{
						intersect.add(dn);
					}
					else
					{
						intersect.add(subtree);
						intersect.add(dn);
					}
				}

				return intersect;
			}
		}

		private Set intersectOtherName(Set permitted, Set otherNames)
		{
			Set intersect = new HashSet(permitted);

			intersect.retainAll(otherNames);

			return intersect;
		}


		private Set unionOtherName(Set permitted, OtherName otherName)
		{
			Set union = new HashSet(permitted);

			union.add(otherName);

			return union;
		}

		private Set intersectEmail(Set permitted, Set emails)
		{
			Set intersect = new HashSet();
			for (Iterator it = emails.iterator(); it.hasNext();)
			{
				string email = extractNameAsString(((GeneralSubtree)it.next()).getBase());

				if (permitted == null)
				{
					if (!string.ReferenceEquals(email, null))
					{
						intersect.add(email);
					}
				}
				else
				{
					Iterator it2 = permitted.iterator();
					while (it2.hasNext())
					{
						string _permitted = (string)it2.next();

						intersectEmail(email, _permitted, intersect);
					}
				}
			}
			return intersect;
		}

		private Set unionEmail(Set excluded, string email)
		{
			if (excluded.isEmpty())
			{
				if (string.ReferenceEquals(email, null))
				{
					return excluded;
				}
				excluded.add(email);
				return excluded;
			}
			else
			{
				Set union = new HashSet();

				Iterator it = excluded.iterator();
				while (it.hasNext())
				{
					string _excluded = (string)it.next();

					unionEmail(_excluded, email, union);
				}

				return union;
			}
		}

		/// <summary>
		/// Returns the intersection of the permitted IP ranges in
		/// <code>permitted</code> with <code>ip</code>.
		/// </summary>
		/// <param name="permitted"> A <code>Set</code> of permitted IP addresses with
		///                  their subnet mask as byte arrays. </param>
		/// <param name="ips">       The IP address with its subnet mask. </param>
		/// <returns> The <code>Set</code> of permitted IP ranges intersected with
		/// <code>ip</code>. </returns>
		private Set intersectIP(Set permitted, Set ips)
		{
			Set intersect = new HashSet();
			for (Iterator it = ips.iterator(); it.hasNext();)
			{
				byte[] ip = ASN1OctetString.getInstance(((GeneralSubtree)it.next()).getBase().getName()).getOctets();
				if (permitted == null)
				{
					if (ip != null)
					{
						intersect.add(ip);
					}
				}
				else
				{
					Iterator it2 = permitted.iterator();
					while (it2.hasNext())
					{
						byte[] _permitted = (byte[])it2.next();
						intersect.addAll(intersectIPRange(_permitted, ip));
					}
				}
			}
			return intersect;
		}

		/// <summary>
		/// Returns the union of the excluded IP ranges in <code>excluded</code>
		/// with <code>ip</code>.
		/// </summary>
		/// <param name="excluded"> A <code>Set</code> of excluded IP addresses with their
		///                 subnet mask as byte arrays. </param>
		/// <param name="ip">       The IP address with its subnet mask. </param>
		/// <returns> The <code>Set</code> of excluded IP ranges unified with
		/// <code>ip</code> as byte arrays. </returns>
		private Set unionIP(Set excluded, byte[] ip)
		{
			if (excluded.isEmpty())
			{
				if (ip == null)
				{
					return excluded;
				}
				excluded.add(ip);

				return excluded;
			}
			else
			{
				Set union = new HashSet();

				Iterator it = excluded.iterator();
				while (it.hasNext())
				{
					byte[] _excluded = (byte[])it.next();
					union.addAll(unionIPRange(_excluded, ip));
				}

				return union;
			}
		}

		/// <summary>
		/// Calculates the union if two IP ranges.
		/// </summary>
		/// <param name="ipWithSubmask1"> The first IP address with its subnet mask. </param>
		/// <param name="ipWithSubmask2"> The second IP address with its subnet mask. </param>
		/// <returns> A <code>Set</code> with the union of both addresses. </returns>
		private Set unionIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
		{
			Set set = new HashSet();

			// difficult, adding always all IPs is not wrong
			if (Arrays.areEqual(ipWithSubmask1, ipWithSubmask2))
			{
				set.add(ipWithSubmask1);
			}
			else
			{
				set.add(ipWithSubmask1);
				set.add(ipWithSubmask2);
			}
			return set;
		}

		/// <summary>
		/// Calculates the interesction if two IP ranges.
		/// </summary>
		/// <param name="ipWithSubmask1"> The first IP address with its subnet mask. </param>
		/// <param name="ipWithSubmask2"> The second IP address with its subnet mask. </param>
		/// <returns> A <code>Set</code> with the single IP address with its subnet
		/// mask as a byte array or an empty <code>Set</code>. </returns>
		private Set intersectIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
		{
			if (ipWithSubmask1.Length != ipWithSubmask2.Length)
			{
				return Collections.EMPTY_SET;
			}
			byte[][] temp = extractIPsAndSubnetMasks(ipWithSubmask1, ipWithSubmask2);
			byte[] ip1 = temp[0];
			byte[] subnetmask1 = temp[1];
			byte[] ip2 = temp[2];
			byte[] subnetmask2 = temp[3];

			byte[][] minMax = minMaxIPs(ip1, subnetmask1, ip2, subnetmask2);
			byte[] mina;
			byte[] maxa;
			maxa = min(minMax[1], minMax[3]);
			mina = max(minMax[0], minMax[2]);

			// minimum IP address must be bigger than max
			if (compareTo(mina, maxa) == 1)
			{
				return Collections.EMPTY_SET;
			}
			// OR keeps all significant bits
			byte[] ip = or(minMax[0], minMax[2]);
			byte[] subnetmask = or(subnetmask1, subnetmask2);
			return Collections.singleton(ipWithSubnetMask(ip, subnetmask));
		}

		/// <summary>
		/// Concatenates the IP address with its subnet mask.
		/// </summary>
		/// <param name="ip">         The IP address. </param>
		/// <param name="subnetMask"> Its subnet mask. </param>
		/// <returns> The concatenated IP address with its subnet mask. </returns>
		private byte[] ipWithSubnetMask(byte[] ip, byte[] subnetMask)
		{
			int ipLength = ip.Length;
			byte[] temp = new byte[ipLength * 2];
			JavaSystem.arraycopy(ip, 0, temp, 0, ipLength);
			JavaSystem.arraycopy(subnetMask, 0, temp, ipLength, ipLength);
			return temp;
		}

		/// <summary>
		/// Splits the IP addresses and their subnet mask.
		/// </summary>
		/// <param name="ipWithSubmask1"> The first IP address with the subnet mask. </param>
		/// <param name="ipWithSubmask2"> The second IP address with the subnet mask. </param>
		/// <returns> An array with two elements. Each element contains the IP address
		/// and the subnet mask in this order. </returns>
		private byte[][] extractIPsAndSubnetMasks(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
		{
			int ipLength = ipWithSubmask1.Length / 2;
			byte[] ip1 = new byte[ipLength];
			byte[] subnetmask1 = new byte[ipLength];
			JavaSystem.arraycopy(ipWithSubmask1, 0, ip1, 0, ipLength);
			JavaSystem.arraycopy(ipWithSubmask1, ipLength, subnetmask1, 0, ipLength);

			byte[] ip2 = new byte[ipLength];
			byte[] subnetmask2 = new byte[ipLength];
			JavaSystem.arraycopy(ipWithSubmask2, 0, ip2, 0, ipLength);
			JavaSystem.arraycopy(ipWithSubmask2, ipLength, subnetmask2, 0, ipLength);
			return new byte[][] {ip1, subnetmask1, ip2, subnetmask2};
		}

		/// <summary>
		/// Based on the two IP addresses and their subnet masks the IP range is
		/// computed for each IP address - subnet mask pair and returned as the
		/// minimum IP address and the maximum address of the range.
		/// </summary>
		/// <param name="ip1">         The first IP address. </param>
		/// <param name="subnetmask1"> The subnet mask of the first IP address. </param>
		/// <param name="ip2">         The second IP address. </param>
		/// <param name="subnetmask2"> The subnet mask of the second IP address. </param>
		/// <returns> A array with two elements. The first/second element contains the
		/// min and max IP address of the first/second IP address and its
		/// subnet mask. </returns>
		private byte[][] minMaxIPs(byte[] ip1, byte[] subnetmask1, byte[] ip2, byte[] subnetmask2)
		{
			int ipLength = ip1.Length;
			byte[] min1 = new byte[ipLength];
			byte[] max1 = new byte[ipLength];

			byte[] min2 = new byte[ipLength];
			byte[] max2 = new byte[ipLength];

			for (int i = 0; i < ipLength; i++)
			{
				min1[i] = (byte)(ip1[i] & subnetmask1[i]);
				max1[i] = (byte)(ip1[i] & subnetmask1[i] | ~subnetmask1[i]);

				min2[i] = (byte)(ip2[i] & subnetmask2[i]);
				max2[i] = (byte)(ip2[i] & subnetmask2[i] | ~subnetmask2[i]);
			}

			return new byte[][]{min1, max1, min2, max2};
		}

		private void checkPermittedEmail(Set permitted, string email)
		{
			if (permitted == null)
			{
				return;
			}

			Iterator it = permitted.iterator();

			while (it.hasNext())
			{
				string str = ((string)it.next());

				if (emailIsConstrained(email, str))
				{
					return;
				}
			}

			if (email.Length == 0 && permitted.size() == 0)
			{
				return;
			}

			throw new NameConstraintValidatorException("Subject email address is not from a permitted subtree.");
		}

		private void checkPermittedOtherName(Set permitted, OtherName name)
		{
			if (permitted == null)
			{
				return;
			}

			Iterator it = permitted.iterator();

			while (it.hasNext())
			{
				OtherName str = ((OtherName)it.next());

				if (otherNameIsConstrained(name, str))
				{
					return;
				}
			}

			throw new NameConstraintValidatorException("Subject OtherName is not from a permitted subtree.");
		}

		private void checkExcludedOtherName(Set excluded, OtherName name)
		{
			if (excluded.isEmpty())
			{
				return;
			}

			Iterator it = excluded.iterator();

			while (it.hasNext())
			{
				OtherName str = OtherName.getInstance(it.next());

				if (otherNameIsConstrained(name, str))
				{
					throw new NameConstraintValidatorException("OtherName is from an excluded subtree.");
				}
			}
		}

		private void checkExcludedEmail(Set excluded, string email)
		{
			if (excluded.isEmpty())
			{
				return;
			}

			Iterator it = excluded.iterator();

			while (it.hasNext())
			{
				string str = (string)it.next();

				if (emailIsConstrained(email, str))
				{
					throw new NameConstraintValidatorException("Email address is from an excluded subtree.");
				}
			}
		}

		/// <summary>
		/// Checks if the IP <code>ip</code> is included in the permitted set
		/// <code>permitted</code>.
		/// </summary>
		/// <param name="permitted"> A <code>Set</code> of permitted IP addresses with
		///                  their subnet mask as byte arrays. </param>
		/// <param name="ip">        The IP address. </param>
		/// <exception cref="NameConstraintValidatorException"> if the IP is not permitted. </exception>
		private void checkPermittedIP(Set permitted, byte[] ip)
		{
			if (permitted == null)
			{
				return;
			}

			Iterator it = permitted.iterator();

			while (it.hasNext())
			{
				byte[] ipWithSubnet = (byte[])it.next();

				if (isIPConstrained(ip, ipWithSubnet))
				{
					return;
				}
			}
			if (ip.Length == 0 && permitted.size() == 0)
			{
				return;
			}
			throw new NameConstraintValidatorException("IP is not from a permitted subtree.");
		}

		/// <summary>
		/// Checks if the IP <code>ip</code> is included in the excluded set
		/// <code>excluded</code>.
		/// </summary>
		/// <param name="excluded"> A <code>Set</code> of excluded IP addresses with their
		///                 subnet mask as byte arrays. </param>
		/// <param name="ip">       The IP address. </param>
		/// <exception cref="NameConstraintValidatorException"> if the IP is excluded. </exception>
		private void checkExcludedIP(Set excluded, byte[] ip)
		{
			if (excluded.isEmpty())
			{
				return;
			}

			Iterator it = excluded.iterator();

			while (it.hasNext())
			{
				byte[] ipWithSubnet = (byte[])it.next();

				if (isIPConstrained(ip, ipWithSubnet))
				{
					throw new NameConstraintValidatorException("IP is from an excluded subtree.");
				}
			}
		}

		/// <summary>
		/// Checks if the IP address <code>ip</code> is constrained by
		/// <code>constraint</code>.
		/// </summary>
		/// <param name="ip">         The IP address. </param>
		/// <param name="constraint"> The constraint. This is an IP address concatenated with
		///                   its subnetmask. </param>
		/// <returns> <code>true</code> if constrained, <code>false</code>
		/// otherwise. </returns>
		private bool isIPConstrained(byte[] ip, byte[] constraint)
		{
			int ipLength = ip.Length;

			if (ipLength != (constraint.Length / 2))
			{
				return false;
			}

			byte[] subnetMask = new byte[ipLength];
			JavaSystem.arraycopy(constraint, ipLength, subnetMask, 0, ipLength);

			byte[] permittedSubnetAddress = new byte[ipLength];

			byte[] ipSubnetAddress = new byte[ipLength];

			// the resulting IP address by applying the subnet mask
			for (int i = 0; i < ipLength; i++)
			{
				permittedSubnetAddress[i] = (byte)(constraint[i] & subnetMask[i]);
				ipSubnetAddress[i] = (byte)(ip[i] & subnetMask[i]);
			}

			return Arrays.areEqual(permittedSubnetAddress, ipSubnetAddress);
		}

		private bool otherNameIsConstrained(OtherName name, OtherName constraint)
		{
			if (constraint.Equals(name))
			{
				return true;
			}

			return false;
		}

		private bool emailIsConstrained(string email, string constraint)
		{
			string sub = email.Substring(email.IndexOf('@') + 1);
			// a particular mailbox
			if (constraint.IndexOf('@') != -1)
			{
				if (email.Equals(constraint, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			// on particular host
			else if (!(constraint[0] == '.'))
			{
				if (sub.Equals(constraint, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			// address in sub domain
			else if (withinDomain(sub, constraint))
			{
				return true;
			}
			return false;
		}

		private bool withinDomain(string testDomain, string domain)
		{
			string tempDomain = domain;
			if (tempDomain.StartsWith(".", StringComparison.Ordinal))
			{
				tempDomain = tempDomain.Substring(1);
			}
			string[] domainParts = Strings.split(tempDomain, '.');
			string[] testDomainParts = Strings.split(testDomain, '.');
			// must have at least one subdomain
			if (testDomainParts.Length <= domainParts.Length)
			{
				return false;
			}
			int d = testDomainParts.Length - domainParts.Length;
			for (int i = -1; i < domainParts.Length; i++)
			{
				if (i == -1)
				{
					if (testDomainParts[i + d].Equals(""))
					{
						return false;
					}
				}
				else if (!domainParts[i].Equals(testDomainParts[i + d], StringComparison.OrdinalIgnoreCase))
				{
					return false;
				}
			}
			return true;
		}

		private void checkPermittedDNS(Set permitted, string dns)
		{
			if (permitted == null)
			{
				return;
			}

			Iterator it = permitted.iterator();

			while (it.hasNext())
			{
				string str = ((string)it.next());

				// is sub domain
				if (withinDomain(dns, str) || dns.Equals(str, StringComparison.OrdinalIgnoreCase))
				{
					return;
				}
			}
			if (dns.Length == 0 && permitted.size() == 0)
			{
				return;
			}
			throw new NameConstraintValidatorException("DNS is not from a permitted subtree.");
		}

		private void checkExcludedDNS(Set excluded, string dns)
		{
			if (excluded.isEmpty())
			{
				return;
			}

			Iterator it = excluded.iterator();

			while (it.hasNext())
			{
				string str = ((string)it.next());

				// is sub domain or the same
				if (withinDomain(dns, str) || dns.Equals(str, StringComparison.OrdinalIgnoreCase))
				{
					throw new NameConstraintValidatorException("DNS is from an excluded subtree.");
				}
			}
		}

		/// <summary>
		/// The common part of <code>email1</code> and <code>email2</code> is
		/// added to the union <code>union</code>. If <code>email1</code> and
		/// <code>email2</code> have nothing in common they are added both.
		/// </summary>
		/// <param name="email1"> Email address constraint 1. </param>
		/// <param name="email2"> Email address constraint 2. </param>
		/// <param name="union">  The union. </param>
		private void unionEmail(string email1, string email2, Set union)
		{
			// email1 is a particular address
			if (email1.IndexOf('@') != -1)
			{
				string _sub = email1.Substring(email1.IndexOf('@') + 1);
				// both are a particular mailbox
				if (email2.IndexOf('@') != -1)
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(_sub, email2))
					{
						union.add(email2);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (_sub.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email2);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
			}
			// email1 specifies a domain
			else if (email1.StartsWith(".", StringComparison.Ordinal))
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email1.IndexOf('@') + 1);
					if (withinDomain(_sub, email1))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2) || email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email2);
					}
					else if (withinDomain(email2, email1))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				else
				{
					if (withinDomain(email2, email1))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
			}
			// email specifies a host
			else
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email1.IndexOf('@') + 1);
					if (_sub.Equals(email1, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2))
					{
						union.add(email2);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
			}
		}

		private void unionURI(string email1, string email2, Set union)
		{
			// email1 is a particular address
			if (email1.IndexOf('@') != -1)
			{
				string _sub = email1.Substring(email1.IndexOf('@') + 1);
				// both are a particular mailbox
				if (email2.IndexOf('@') != -1)
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(_sub, email2))
					{
						union.add(email2);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (_sub.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email2);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
			}
			// email1 specifies a domain
			else if (email1.StartsWith(".", StringComparison.Ordinal))
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email1.IndexOf('@') + 1);
					if (withinDomain(_sub, email1))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2) || email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email2);
					}
					else if (withinDomain(email2, email1))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				else
				{
					if (withinDomain(email2, email1))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
			}
			// email specifies a host
			else
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email1.IndexOf('@') + 1);
					if (_sub.Equals(email1, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2))
					{
						union.add(email2);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						union.add(email1);
					}
					else
					{
						union.add(email1);
						union.add(email2);
					}
				}
			}
		}

		private Set intersectDNS(Set permitted, Set dnss)
		{
			Set intersect = new HashSet();
			for (Iterator it = dnss.iterator(); it.hasNext();)
			{
				string dns = extractNameAsString(((GeneralSubtree)it.next()).getBase());
				if (permitted == null)
				{
					if (!string.ReferenceEquals(dns, null))
					{
						intersect.add(dns);
					}
				}
				else
				{
					Iterator _iter = permitted.iterator();
					while (_iter.hasNext())
					{
						string _permitted = (string)_iter.next();

						if (withinDomain(_permitted, dns))
						{
							intersect.add(_permitted);
						}
						else if (withinDomain(dns, _permitted))
						{
							intersect.add(dns);
						}
					}
				}
			}

			return intersect;
		}

		private Set unionDNS(Set excluded, string dns)
		{
			if (excluded.isEmpty())
			{
				if (string.ReferenceEquals(dns, null))
				{
					return excluded;
				}
				excluded.add(dns);

				return excluded;
			}
			else
			{
				Set union = new HashSet();

				Iterator _iter = excluded.iterator();
				while (_iter.hasNext())
				{
					string _permitted = (string)_iter.next();

					if (withinDomain(_permitted, dns))
					{
						union.add(dns);
					}
					else if (withinDomain(dns, _permitted))
					{
						union.add(_permitted);
					}
					else
					{
						union.add(_permitted);
						union.add(dns);
					}
				}

				return union;
			}
		}

		/// <summary>
		/// The most restricting part from <code>email1</code> and
		/// <code>email2</code> is added to the intersection <code>intersect</code>.
		/// </summary>
		/// <param name="email1">    Email address constraint 1. </param>
		/// <param name="email2">    Email address constraint 2. </param>
		/// <param name="intersect"> The intersection. </param>
		private void intersectEmail(string email1, string email2, Set intersect)
		{
			// email1 is a particular address
			if (email1.IndexOf('@') != -1)
			{
				string _sub = email1.Substring(email1.IndexOf('@') + 1);
				// both are a particular mailbox
				if (email2.IndexOf('@') != -1)
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(_sub, email2))
					{
						intersect.add(email1);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (_sub.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
				}
			}
			// email specifies a domain
			else if (email1.StartsWith(".", StringComparison.Ordinal))
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email1.IndexOf('@') + 1);
					if (withinDomain(_sub, email1))
					{
						intersect.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2) || email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
					else if (withinDomain(email2, email1))
					{
						intersect.add(email2);
					}
				}
				else
				{
					if (withinDomain(email2, email1))
					{
						intersect.add(email2);
					}
				}
			}
			// email1 specifies a host
			else
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email2.IndexOf('@') + 1);
					if (_sub.Equals(email1, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2))
					{
						intersect.add(email1);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
				}
			}
		}

		private void checkExcludedURI(Set excluded, string uri)
		{
			if (excluded.isEmpty())
			{
				return;
			}

			Iterator it = excluded.iterator();

			while (it.hasNext())
			{
				string str = ((string)it.next());

				if (isUriConstrained(uri, str))
				{
					throw new NameConstraintValidatorException("URI is from an excluded subtree.");
				}
			}
		}

		private Set intersectURI(Set permitted, Set uris)
		{
			Set intersect = new HashSet();
			for (Iterator it = uris.iterator(); it.hasNext();)
			{
				string uri = extractNameAsString(((GeneralSubtree)it.next()).getBase());
				if (permitted == null)
				{
					if (!string.ReferenceEquals(uri, null))
					{
						intersect.add(uri);
					}
				}
				else
				{
					Iterator _iter = permitted.iterator();
					while (_iter.hasNext())
					{
						string _permitted = (string)_iter.next();
						intersectURI(_permitted, uri, intersect);
					}
				}
			}
			return intersect;
		}

		private Set unionURI(Set excluded, string uri)
		{
			if (excluded.isEmpty())
			{
				if (string.ReferenceEquals(uri, null))
				{
					return excluded;
				}
				excluded.add(uri);

				return excluded;
			}
			else
			{
				Set union = new HashSet();

				Iterator _iter = excluded.iterator();
				while (_iter.hasNext())
				{
					string _excluded = (string)_iter.next();

					unionURI(_excluded, uri, union);
				}

				return union;
			}
		}

		private void intersectURI(string email1, string email2, Set intersect)
		{
			// email1 is a particular address
			if (email1.IndexOf('@') != -1)
			{
				string _sub = email1.Substring(email1.IndexOf('@') + 1);
				// both are a particular mailbox
				if (email2.IndexOf('@') != -1)
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(_sub, email2))
					{
						intersect.add(email1);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (_sub.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
				}
			}
			// email specifies a domain
			else if (email1.StartsWith(".", StringComparison.Ordinal))
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email1.IndexOf('@') + 1);
					if (withinDomain(_sub, email1))
					{
						intersect.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2) || email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
					else if (withinDomain(email2, email1))
					{
						intersect.add(email2);
					}
				}
				else
				{
					if (withinDomain(email2, email1))
					{
						intersect.add(email2);
					}
				}
			}
			// email1 specifies a host
			else
			{
				if (email2.IndexOf('@') != -1)
				{
					string _sub = email2.Substring(email2.IndexOf('@') + 1);
					if (_sub.Equals(email1, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email2);
					}
				}
				// email2 specifies a domain
				else if (email2.StartsWith(".", StringComparison.Ordinal))
				{
					if (withinDomain(email1, email2))
					{
						intersect.add(email1);
					}
				}
				// email2 specifies a particular host
				else
				{
					if (email1.Equals(email2, StringComparison.OrdinalIgnoreCase))
					{
						intersect.add(email1);
					}
				}
			}
		}

		private void checkPermittedURI(Set permitted, string uri)
		{
			if (permitted == null)
			{
				return;
			}

			Iterator it = permitted.iterator();

			while (it.hasNext())
			{
				string str = ((string)it.next());

				if (isUriConstrained(uri, str))
				{
					return;
				}
			}
			if (uri.Length == 0 && permitted.size() == 0)
			{
				return;
			}
			throw new NameConstraintValidatorException("URI is not from a permitted subtree.");
		}

		private bool isUriConstrained(string uri, string constraint)
		{
			string host = extractHostFromURL(uri);
			// a host
			if (!constraint.StartsWith(".", StringComparison.Ordinal))
			{
				if (host.Equals(constraint, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}

			// in sub domain or domain
			else if (withinDomain(host, constraint))
			{
				return true;
			}

			return false;
		}

		private static string extractHostFromURL(string url)
		{
			// see RFC 1738
			// remove ':' after protocol, e.g. http:
			string sub = url.Substring(url.IndexOf(':') + 1);
			// extract host from Common Internet Scheme Syntax, e.g. http://
			if (sub.IndexOf("//", StringComparison.Ordinal) != -1)
			{
				sub = sub.Substring(sub.IndexOf("//", StringComparison.Ordinal) + 2);
			}
			// first remove port, e.g. http://test.com:21
			if (sub.LastIndexOf(':') != -1)
			{
				sub = sub.Substring(0, sub.LastIndexOf(':'));
			}
			// remove user and password, e.g. http://john:password@test.com
			sub = sub.Substring(sub.IndexOf(':') + 1);
			sub = sub.Substring(sub.IndexOf('@') + 1);
			// remove local parts, e.g. http://test.com/bla
			if (sub.IndexOf('/') != -1)
			{
				sub = sub.Substring(0, sub.IndexOf('/'));
			}
			return sub;
		}

		private string extractNameAsString(GeneralName name)
		{
			return DERIA5String.getInstance(name.getName()).getString();
		}

		/// <summary>
		/// Returns the maximum IP address.
		/// </summary>
		/// <param name="ip1"> The first IP address. </param>
		/// <param name="ip2"> The second IP address. </param>
		/// <returns> The maximum IP address. </returns>
		private static byte[] max(byte[] ip1, byte[] ip2)
		{
			for (int i = 0; i < ip1.Length; i++)
			{
				if ((ip1[i] & 0xFFFF) > (ip2[i] & 0xFFFF))
				{
					return ip1;
				}
			}
			return ip2;
		}

		/// <summary>
		/// Returns the minimum IP address.
		/// </summary>
		/// <param name="ip1"> The first IP address. </param>
		/// <param name="ip2"> The second IP address. </param>
		/// <returns> The minimum IP address. </returns>
		private static byte[] min(byte[] ip1, byte[] ip2)
		{
			for (int i = 0; i < ip1.Length; i++)
			{
				if ((ip1[i] & 0xFFFF) < (ip2[i] & 0xFFFF))
				{
					return ip1;
				}
			}
			return ip2;
		}

		/// <summary>
		/// Compares IP address <code>ip1</code> with <code>ip2</code>. If ip1
		/// is equal to ip2 0 is returned. If ip1 is bigger 1 is returned, -1
		/// otherwise.
		/// </summary>
		/// <param name="ip1"> The first IP address. </param>
		/// <param name="ip2"> The second IP address. </param>
		/// <returns> 0 if ip1 is equal to ip2, 1 if ip1 is bigger, -1 otherwise. </returns>
		private static int compareTo(byte[] ip1, byte[] ip2)
		{
			if (Arrays.areEqual(ip1, ip2))
			{
				return 0;
			}
			if (Arrays.areEqual(max(ip1, ip2), ip1))
			{
				return 1;
			}
			return -1;
		}

		/// <summary>
		/// Returns the logical OR of the IP addresses <code>ip1</code> and
		/// <code>ip2</code>.
		/// </summary>
		/// <param name="ip1"> The first IP address. </param>
		/// <param name="ip2"> The second IP address. </param>
		/// <returns> The OR of <code>ip1</code> and <code>ip2</code>. </returns>
		private static byte[] or(byte[] ip1, byte[] ip2)
		{
			byte[] temp = new byte[ip1.Length];
			for (int i = 0; i < ip1.Length; i++)
			{
				temp[i] = (byte)(ip1[i] | ip2[i]);
			}
			return temp;
		}

		private int hashCollection(Collection coll)
		{
			if (coll == null)
			{
				return 0;
			}
			int hash = 0;
			Iterator it1 = coll.iterator();
			while (it1.hasNext())
			{
				object o = it1.next();
				if (o is byte[])
				{
					hash += Arrays.GetHashCode((byte[])o);
				}
				else
				{
					hash += o.GetHashCode();
				}
			}
			return hash;
		}

		private bool collectionsAreEqual(Collection coll1, Collection coll2)
		{
			if (coll1 == coll2)
			{
				return true;
			}
			if (coll1 == null || coll2 == null)
			{
				return false;
			}
			if (coll1.size() != coll2.size())
			{
				return false;
			}
			Iterator it1 = coll1.iterator();

			while (it1.hasNext())
			{
				object a = it1.next();
				Iterator it2 = coll2.iterator();
				bool found = false;
				while (it2.hasNext())
				{
					object b = it2.next();
					if (equals(a, b))
					{
						found = true;
						break;
					}
				}
				if (!found)
				{
					return false;
				}
			}
			return true;
		}

		private bool equals(object o1, object o2)
		{
			if (o1 == o2)
			{
				return true;
			}
			if (o1 == null || o2 == null)
			{
				return false;
			}
			if (o1 is byte[] && o2 is byte[])
			{
				return Arrays.areEqual((byte[])o1, (byte[])o2);
			}
			else
			{
				return o1.Equals(o2);
			}
		}

		/// <summary>
		/// Stringifies an IPv4 or v6 address with subnet mask.
		/// </summary>
		/// <param name="ip"> The IP with subnet mask. </param>
		/// <returns> The stringified IP address. </returns>
		private string stringifyIP(byte[] ip)
		{
			StringBuilder temp = new StringBuilder();
			for (int i = 0; i < ip.Length / 2; i++)
			{
				if (temp.length() > 0)
				{
					temp.append(".");
				}
				temp.append(Convert.ToString(ip[i] & 0x00FF));
			}

			temp.append("/");
			bool first = true;
			for (int i = ip.Length / 2; i < ip.Length; i++)
			{
				if (first)
				{
					first = false;
				}
				else
				{
					temp.append(".");
				}
				temp.append(Convert.ToString(ip[i] & 0x00FF));
			}

			return temp.ToString();
		}

		private string stringifyIPCollection(Set ips)
		{
			StringBuilder temp = new StringBuilder();
			temp.append("[");
			for (Iterator it = ips.iterator(); it.hasNext();)
			{
				if (temp.length() > 1)
				{
					temp.append(",");
				}
				temp.append(stringifyIP((byte[])it.next()));
			}
			temp.append("]");
			return temp.ToString();
		}

		private string stringifyOtherNameCollection(Set otherNames)
		{
			StringBuilder temp = new StringBuilder();
			temp.append("[");
			for (Iterator it = otherNames.iterator(); it.hasNext();)
			{
				if (temp.length() > 1)
				{
					temp.append(",");
				}
				OtherName name = OtherName.getInstance(it.next());
				temp.append(name.getTypeID().getId());
				temp.append(":");
				try
				{
					temp.append(Hex.toHexString(name.getValue().toASN1Primitive().getEncoded()));
				}
				catch (IOException e)
				{
					temp.append(e.ToString());
				}
			}
			temp.append("]");
			return temp.ToString();
		}
	}

}