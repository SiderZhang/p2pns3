#pragma once
#include "Segment.h"

#include <list>
#include <map>
#include <vector>
#include <sstream>
using namespace std;

class Video
{
private:
	static int chokeCount;
	static int layerCount;

	static Video instance;

	// 全部的数据
	vector<vector<Segment*>* > segmentMap;

	// 正在缓冲的数据
	map<pair<int, int>, Segment*> waitingSegment;

	int segCount;
	float triangleIndex;
	float avgLayerCount;
public:
	Video(void);
	~Video(void);

	static int totalSize()
	{
		return (chokeCount * layerCount) * SEG_SIZE;
	};
	
	// 获得总的视频长度，以多少段落计算
	static int getTotalChokeCount()
	{
		return chokeCount;
	}

	// 获得总的层数
	static int getLayerCount()
	{
		return layerCount;
	}

	static void setTotalChokeCount(int count)
	{
		chokeCount = count;
	}

	static Video& getInstance()
	{
		return instance;
	}

	static void setLayerCount(int count)
	{
		layerCount = count;
	}

	static Video* getFullVideoCopy();
	
	static Video* getEmptyVideoCopy();

	// 计算当前的视频
	float calcDataRate(int decodedLimit);

	// 获得当前缓冲的进度
	int getBuffedIndex();

	void startBuffSeg(Segment* seg);

	Segment* getSegment(int index, int layer);

	bool hasSegment(int index, int layer);

	int chokeLayerCount(int index);

	float getTrangleIndex()
	{
		return this->triangleIndex;
	}

	int getSegCount()
	{
		return this->segCount;
	}

	void updateTrangleIndex(int decodeLimit, stringstream& logger);

	// 判断某个段落缓冲的进度
	int BufferedLayer(int index);

	float AvgBufferedLayer()
	{
		return this->avgLayerCount;
	}
private:
	void insertSegment(Segment* seg);
};

