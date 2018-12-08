namespace org.bouncycastle.cms
{

	using Iterable = org.bouncycastle.util.Iterable;

	public class SignerInformationStore : Iterable<SignerInformation>
	{
		private List all = new ArrayList();
		private Map table = new HashMap();

		/// <summary>
		/// Create a store containing a single SignerInformation object.
		/// </summary>
		/// <param name="signerInfo"> the signer information to contain. </param>
		public SignerInformationStore(SignerInformation signerInfo)
		{
			this.all = new ArrayList(1);
			this.all.add(signerInfo);

			SignerId sid = signerInfo.getSID();

			table.put(sid, all);
		}

		/// <summary>
		/// Create a store containing a collection of SignerInformation objects.
		/// </summary>
		/// <param name="signerInfos"> a collection signer information objects to contain. </param>
		public SignerInformationStore(Collection<SignerInformation> signerInfos)
		{
			Iterator it = signerInfos.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				SignerId sid = signer.getSID();

				List list = (ArrayList)table.get(sid);
				if (list == null)
				{
					list = new ArrayList(1);
					table.put(sid, list);
				}

				list.add(signer);
			}

			this.all = new ArrayList(signerInfos);
		}

		/// <summary>
		/// Return the first SignerInformation object that matches the
		/// passed in selector. Null if there are no matches.
		/// </summary>
		/// <param name="selector"> to identify a signer </param>
		/// <returns> a single SignerInformation object. Null if none matches. </returns>
		public virtual SignerInformation get(SignerId selector)
		{
			Collection list = getSigners(selector);

			return list.size() == 0 ? null : (SignerInformation) list.iterator().next();
		}

		/// <summary>
		/// Return the number of signers in the collection.
		/// </summary>
		/// <returns> number of signers identified. </returns>
		public virtual int size()
		{
			return all.size();
		}

		/// <summary>
		/// Return all signers in the collection
		/// </summary>
		/// <returns> a collection of signers. </returns>
		public virtual Collection<SignerInformation> getSigners()
		{
			return new ArrayList(all);
		}

		/// <summary>
		/// Return possible empty collection with signers matching the passed in SignerId
		/// </summary>
		/// <param name="selector"> a signer id to select against. </param>
		/// <returns> a collection of SignerInformation objects. </returns>
		public virtual Collection<SignerInformation> getSigners(SignerId selector)
		{
			if (selector.getIssuer() != null && selector.getSubjectKeyIdentifier() != null)
			{
				List results = new ArrayList();

				Collection match1 = getSigners(new SignerId(selector.getIssuer(), selector.getSerialNumber()));

				if (match1 != null)
				{
					results.addAll(match1);
				}

				Collection match2 = getSigners(new SignerId(selector.getSubjectKeyIdentifier()));

				if (match2 != null)
				{
					results.addAll(match2);
				}

				return results;
			}
			else
			{
				List list = (ArrayList)table.get(selector);

				return list == null ? new ArrayList() : new ArrayList(list);
			}
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<SignerInformation> iterator()
		{
			return getSigners().iterator();
		}
	}

}