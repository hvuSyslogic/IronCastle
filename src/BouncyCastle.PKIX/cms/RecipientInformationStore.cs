namespace org.bouncycastle.cms
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using org.bouncycastle.util;

	public class RecipientInformationStore : Iterable<RecipientInformation>
	{
		private readonly List all; //ArrayList[RecipientInformation]
		private readonly Map table = new HashMap(); // HashMap[RecipientID, ArrayList[RecipientInformation]]

		/// <summary>
		/// Create a store containing a single RecipientInformation object.
		/// </summary>
		/// <param name="recipientInformation"> the signer information to contain. </param>
		public RecipientInformationStore(RecipientInformation recipientInformation)
		{
			this.all = new ArrayList(1);
			this.all.add(recipientInformation);

			RecipientId sid = recipientInformation.getRID();

			table.put(sid, all);
		}

		public RecipientInformationStore(Collection<RecipientInformation> recipientInfos)
		{
			Iterator it = recipientInfos.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipientInformation = (RecipientInformation)it.next();
				RecipientId rid = recipientInformation.getRID();

				List list = (ArrayList)table.get(rid);
				if (list == null)
				{
					list = new ArrayList(1);
					table.put(rid, list);
				}

				list.add(recipientInformation);
			}

			this.all = new ArrayList(recipientInfos);
		}

		/// <summary>
		/// Return the first RecipientInformation object that matches the
		/// passed in selector. Null if there are no matches.
		/// </summary>
		/// <param name="selector"> to identify a recipient </param>
		/// <returns> a single RecipientInformation object. Null if none matches. </returns>
		public virtual RecipientInformation get(RecipientId selector)
		{
			Collection list = getRecipients(selector);

			return list.size() == 0 ? null : (RecipientInformation)list.iterator().next();
		}

		/// <summary>
		/// Return the number of recipients in the collection.
		/// </summary>
		/// <returns> number of recipients identified. </returns>
		public virtual int size()
		{
			return all.size();
		}

		/// <summary>
		/// Return all recipients in the collection
		/// </summary>
		/// <returns> a collection of recipients. </returns>
		public virtual Collection<RecipientInformation> getRecipients()
		{
			return new ArrayList(all);
		}

		/// <summary>
		/// Return possible empty collection with recipients matching the passed in RecipientId
		/// </summary>
		/// <param name="selector"> a recipient id to select against. </param>
		/// <returns> a collection of RecipientInformation objects. </returns>
		public virtual Collection<Recipient> getRecipients(RecipientId selector)
		{
			if (selector is KeyTransRecipientId)
			{
				KeyTransRecipientId keyTrans = (KeyTransRecipientId)selector;

				X500Name issuer = keyTrans.getIssuer();
				byte[] subjectKeyId = keyTrans.getSubjectKeyIdentifier();

				if (issuer != null && subjectKeyId != null)
				{
					List results = new ArrayList();

					Collection match1 = getRecipients(new KeyTransRecipientId(issuer, keyTrans.getSerialNumber()));
					if (match1 != null)
					{
						results.addAll(match1);
					}

					Collection match2 = getRecipients(new KeyTransRecipientId(subjectKeyId));
					if (match2 != null)
					{
						results.addAll(match2);
					}

					return results;
				}
			}

			List list = (ArrayList)table.get(selector);

			return list == null ? new ArrayList() : new ArrayList(list);
		}


		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<RecipientInformation> iterator()
		{
			return getRecipients().iterator();
		}
	}

}