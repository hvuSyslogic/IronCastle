namespace org.bouncycastle.cert.dane
{
	using Selector = org.bouncycastle.util.Selector;

	public class DANEEntrySelector : Selector
	{
		private readonly string domainName;

		public DANEEntrySelector(string domainName)
		{
			this.domainName = domainName;
		}

		public virtual bool match(object obj)
		{
			DANEEntry dEntry = (DANEEntry)obj;

			return dEntry.getDomainName().Equals(domainName);
		}

		public virtual object clone()
		{
			return this;
		}

		public virtual string getDomainName()
		{
			return domainName;
		}
	}

}