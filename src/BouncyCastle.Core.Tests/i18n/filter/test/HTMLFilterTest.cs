namespace org.bouncycastle.i18n.filter.test
{

	using TestCase = junit.framework.TestCase;

	public class HTMLFilterTest : TestCase
	{

		private const string test1 = "hello world";

		private const string test2 = "<script></script>";

		private const string test3 = "javascript:attack()";

		private const string test4 = @"""hello""";

		public virtual void testDoFilter()
		{
			Filter dummy = new HTMLFilter();

			assertEquals("No filtering", "hello world", dummy.doFilter(test1));
			assertEquals("script tags", "&#60script&#62&#60/script&#62", dummy.doFilter(test2));
			assertEquals("javascript link", "javascript:attack&#40&#41", dummy.doFilter(test3));
			assertEquals("", "&#34hello&#34", dummy.doFilter(test4));
		}

	}

}