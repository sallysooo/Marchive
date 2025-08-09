# 콘솔 테스트
from langchain_openai import ChatOpenAI
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
vectordb = Chroma(persist_directory="indexes/chroma", collection_name="torch_docs")
retriever = vectordb.as_retriever(search_kwargs={"k": 4, "filter": {"version": "2.4"}})

prompt = ChatPromptTemplate.from_template(
    "Use the context to answer and include short citations (metadata.source_md).\n\n"
    "Question: {input}\n\nContext:\n{context}"
)
doc_chain = create_stuff_documents_chain(llm, prompt)
qa = create_retrieval_chain(retriever, doc_chain)
print(qa.invoke({"input": "What allows tensors to be tracked by autograd? ('v2.4' 기준)"}))
