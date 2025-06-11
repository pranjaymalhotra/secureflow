import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileText, Github, Upload, AlertCircle, X, Check, Loader2, FolderOpen } from 'lucide-react';
import { toast } from 'sonner';
import { useMutation } from '@tanstack/react-query';
import { AxiosResponse } from 'axios';

import { scanAPI } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';

interface DirectoryInputProps extends React.DetailedHTMLProps<React.InputHTMLAttributes<HTMLInputElement>, HTMLInputElement> {
  webkitdirectory?: string;
  directory?: string;
}

interface ScanResponse {
  job_id: string;
  status: string;
  message: string;
}

interface ScanGitHubRequest {
  github_url: string;
}

export default function AnalysisPage() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'upload' | 'github'>('upload');
  const [files, setFiles] = useState<File[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [githubUrl, setGithubUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [validatingFiles, setValidatingFiles] = useState(false);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [showUploadDialog, setShowUploadDialog] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  // Accepted file extensions for code analysis
  const acceptedExtensions = [
    '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h', '.cs',
    '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.sh', '.html', '.css', '.scss',
    '.md', '.json', '.yaml', '.yml', '.toml', '.ini', '.sql'
  ];

  // Upload files mutation with better error handling
  const uploadMutation = useMutation<AxiosResponse<ScanResponse>, unknown, FormData>({
    mutationFn: (formData) => {
      setIsLoading(true);
      setProcessingProgress(0);
      
      // More realistic progress simulation
      let progressCounter = 0;
      const progressInterval = setInterval(() => {
        progressCounter++;
        const increment = Math.max(0.5, 8 * Math.exp(-progressCounter/10));
        setProcessingProgress(prev => {
          if (prev >= 95) {
            clearInterval(progressInterval);
            return prev;
          }
          return Math.min(95, prev + increment);
        });
      }, 700);

      return scanAPI.uploadFiles(formData)
        .catch(error => {
          if (error.code === 'ECONNABORTED' || error.message?.includes('network') || 
              error.message?.includes('connection') || error.message?.includes('ECONNREFUSED')) {
            throw new Error('Network connection issue. Please check if the server is running and try again.');
          }
          throw error;
        })
        .finally(() => {
          clearInterval(progressInterval);
          setProcessingProgress(100);
        });
    },
    onSuccess: (response) => {
      toast.success('Files uploaded successfully');
      navigate(`/jobs?highlight=${response.data.job_id}`);
    },
    onError: (error: any) => {
      if (error.message?.includes('Network connection')) {
        toast.error(error.message);
      } else if (error.response?.status === 403) {
        toast.error('Authentication required. Please log in again.');
      } else if (error.message?.includes('ECONNREFUSED')) {
        toast.error('Cannot connect to server. Please ensure the backend is running.');
      } else {
        toast.error(error.response?.data?.detail || 'Upload failed');
      }
      setIsLoading(false);
      setProcessingProgress(0);
    },
  });

  // GitHub scan mutation with better error handling
  const githubMutation = useMutation<AxiosResponse<ScanResponse>, unknown, string>({
    mutationFn: (url) => {
      setIsLoading(true);
      setProcessingProgress(0);
      
      const progressInterval = setInterval(() => {
        setProcessingProgress(prev => {
          if (prev >= 95) {
            clearInterval(progressInterval);
            return prev;
          }
          return prev + Math.random() * 8;
        });
      }, 600);

      return scanAPI.scanGitHub({ github_url: url })
        .catch(error => {
          if (error.message?.includes('ECONNREFUSED')) {
            throw new Error('Cannot connect to server. Please ensure the backend is running.');
          }
          throw error;
        })
        .finally(() => {
          clearInterval(progressInterval);
          setProcessingProgress(100);
        });
    },
    onSuccess: (response) => {
      toast.success('GitHub repository analysis started');
      navigate(`/jobs?highlight=${response.data.job_id}`);
    },
    onError: (error: any) => {
      if (error.message?.includes('Cannot connect to server')) {
        toast.error(error.message);
      } else {
        toast.error(error.response?.data?.detail || 'GitHub scan failed');
      }
      setIsLoading(false);
      setProcessingProgress(0);
    },
  });

  // Helper functions
  const isFileSupported = (filename: string) => {
    const ext = `.${filename.split('.').pop()?.toLowerCase()}`;
    return acceptedExtensions.includes(ext);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.items) {
      processDataTransferItems(e.dataTransfer.items);
    } else {
      e.dataTransfer.files && handleFileSelect(e.dataTransfer.files);
    }
  };

  const processDataTransferItems = async (items: DataTransferItemList) => {
    setValidatingFiles(true);
    try {
      const collected: File[] = [];

      const recurse = async (entry: any, path = '') => {
        if (entry.isFile) {
          await new Promise<void>(resolve => {
            entry.file((file: File) => {
              if (isFileSupported(file.name)) {
                Object.assign(file, { path: path + entry.name });
                collected.push(file);
              }
              resolve();
            });
          });
        } else if (entry.isDirectory) {
          const reader = entry.createReader();
          const entries = await new Promise<any[]>((res, rej) => reader.readEntries(res, rej));
          for (const e of entries) {
            await recurse(e, path + entry.name + '/');
          }
        }
      };

      await Promise.all(
        Array.from(items).map(item => {
          const entry = item.webkitGetAsEntry();
          return entry ? recurse(entry) : Promise.resolve();
        })
      );

      if (collected.length > 0) {
        setFiles(prev => [...prev, ...collected]);
        toast.success(`${collected.length} file${collected.length > 1 ? 's' : ''} added`);
      } else {
        toast.info('No supported code files found');
      }
    } catch {
      toast.error('Error processing dropped items');
    } finally {
      setValidatingFiles(false);
    }
  };

  const handleFileSelect = (fileList: FileList) => {
    setValidatingFiles(true);
    const good: File[] = [];
    Array.from(fileList).forEach(f => {
      if (isFileSupported(f.name)) good.push(f);
    });
    if (good.length) {
      setFiles(prev => [...prev, ...good]);
      toast.success(`${good.length} file${good.length > 1 ? 's' : ''} added`);
    } else {
      toast.info('No supported code files found');
    }
    setValidatingFiles(false);
  };

  const removeFile = (idx: number) => {
    setFiles(prev => prev.filter((_, i) => i !== idx));
  };

  // Fixed clearFiles function - now actually used
  const clearFiles = () => {
    setFiles([]);
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (folderInputRef.current) folderInputRef.current.value = '';
    toast.info('All files cleared');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setProcessingProgress(0);

    if (activeTab === 'upload') {
      if (!files.length) {
        toast.error('Please select at least one file');
        setIsLoading(false);
        return;
      }
      const fd = new FormData();
      files.forEach(f => fd.append('files', f, (f as any).path || f.name));
      uploadMutation.mutate(fd);
    } else {
      if (!githubUrl) {
        toast.error('Please enter a GitHub repository URL');
        setIsLoading(false);
        return;
      }
      if (!githubUrl.startsWith('https://github.com/')) {
        toast.error('Please enter a valid GitHub repository URL');
        setIsLoading(false);
        return;
      }
      githubMutation.mutate(githubUrl);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">New Security Analysis</h1>
        <p className="mt-1 text-sm text-gray-400">
          Upload code files or provide a GitHub repository URL to analyze for security issues
        </p>
      </div>

      {/* Analysis Type Selection */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Choose Analysis Type</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
          <button
            type="button"
            disabled={isLoading}
            onClick={() => setActiveTab('upload')}
            className={`flex items-center p-4 rounded-lg border-2 transition-colors ${
              activeTab === 'upload'
                ? 'border-blue-500 bg-blue-900/20'
                : 'border-gray-600 hover:border-gray-500'
            }`}
          >
            <Upload className="h-8 w-8 text-blue-400 mr-4" />
            <div>
              <h3 className="font-medium text-white">Upload Files</h3>
              <p className="text-sm text-gray-400">Upload local code files</p>
            </div>
          </button>
          <button
            type="button"
            disabled={isLoading}
            onClick={() => setActiveTab('github')}
            className={`flex items-center p-4 rounded-lg border-2 transition-colors ${
              activeTab === 'github'
                ? 'border-blue-500 bg-blue-900/20'
                : 'border-gray-600 hover:border-gray-500'
            }`}
          >
            <Github className="h-8 w-8 text-blue-400 mr-4" />
            <div>
              <h3 className="font-medium text-white">GitHub Repository</h3>
              <p className="text-sm text-gray-400">Analyze a public GitHub repo</p>
            </div>
          </button>
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        {activeTab === 'upload' ? (
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">File Upload</h2>
              <p className="card-description">
                Select code files or folders to analyze for security vulnerabilities
              </p>
            </div>
            <div className="p-4">
              {/* Hidden file inputs */}
              <input
                type="file"
                multiple
                className="hidden"
                onChange={(e) => e.target.files && handleFileSelect(e.target.files)}
                ref={fileInputRef}
                disabled={isLoading}
                id="file-upload"
              />

              <input
                type="file"
                multiple
                {...{ webkitdirectory: '', directory: '' } as DirectoryInputProps}
                className="hidden"
                onChange={(e) => e.target.files && handleFileSelect(e.target.files)}
                ref={folderInputRef}
                disabled={isLoading}
                id="folder-upload"
              />

              {!isLoading ? (
                <div
                  className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
                    isDragging
                      ? 'border-blue-500 bg-blue-900/20'
                      : 'border-gray-600 hover:border-gray-500'
                  }`}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => setShowUploadDialog(true)}
                >
                  <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-white font-medium mb-1">
                    Drag &amp; drop files or folders, or click to browse
                  </p>
                  <p className="text-xs text-gray-400">
                    Supports code files (.py, .js, .ts, .java, .cpp, etc.)
                  </p>
                </div>
              ) : (
                <div className="border-2 border-gray-700 rounded-lg p-8 text-center bg-gray-800/50">
                  <div className="flex flex-col items-center justify-center">
                    {processingProgress > 0 ? (
                      <>
                        <div className="relative h-20 w-20 mb-4">
                          <div className="absolute inset-0 flex items-center justify-center">
                            <span className="text-sm font-medium text-blue-400">
                              {Math.round(processingProgress)}%
                            </span>
                          </div>
                          <svg className="h-20 w-20" viewBox="0 0 100 100">
                            <circle
                              className="text-gray-700"
                              strokeWidth="8"
                              stroke="currentColor"
                              fill="transparent"
                              r="42"
                              cx="50"
                              cy="50"
                            />
                            <circle
                              className="text-blue-500"
                              strokeWidth="8"
                              strokeLinecap="round"
                              stroke="currentColor"
                              fill="transparent"
                              r="42"
                              cx="50"
                              cy="50"
                              style={{
                                strokeDasharray: 264,
                                strokeDashoffset: 264 - (processingProgress / 100) * 264,
                                transition: 'stroke-dashoffset 0.5s ease-in-out',
                              }}
                            />
                          </svg>
                        </div>
                        <p className="text-gray-300 font-medium mb-1">Processing your code...</p>
                        <p className="text-xs text-gray-500">This may take a few moments</p>
                      </>
                    ) : validatingFiles ? (
                      <>
                        <Loader2 className="h-12 w-12 text-blue-400 animate-spin mb-4" />
                        <p className="text-gray-300 font-medium mb-1">Validating files...</p>
                        <p className="text-xs text-gray-500">Checking file types and preparing upload</p>
                      </>
                    ) : (
                      <>
                        <LoadingSpinner size="large" />
                        <p className="text-gray-300 font-medium mt-4 mb-1">Uploading files...</p>
                        <p className="text-xs text-gray-500">Preparing your security analysis</p>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* File list with clear button */}
              {files.length > 0 && !isLoading && (
                <div className="mt-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-sm font-medium text-white">
                      Selected Files ({files.length})
                    </h3>
                    <button
                      type="button"
                      onClick={clearFiles}
                      className="text-xs text-red-400 hover:text-red-300"
                    >
                      Clear All
                    </button>
                  </div>
                  <div className="space-y-2 max-h-40 overflow-y-auto">
                    {files.map((file, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between py-2 px-3 bg-gray-700 rounded-lg"
                      >
                        <div className="flex items-center space-x-3">
                          <FileText className="h-4 w-4 text-blue-400 flex-shrink-0" />
                          <span className="text-sm text-white truncate">
                            {(file as any).path || file.name}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs text-gray-400">
                            {(file.size / 1024).toFixed(1)} KB
                          </span>
                          <button
                            type="button"
                            onClick={() => removeFile(idx)}
                            className="text-red-400 hover:text-red-300"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">GitHub Repository</h2>
              <p className="card-description">
                Enter a GitHub repository URL to analyze for security issues
              </p>
            </div>
            <div className="space-y-4 p-4">
              <div>
                <label htmlFor="github-url" className="block text-sm font-medium text-gray-300 mb-2">
                  Repository URL
                </label>
                <input
                  id="github-url"
                  type="url"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/username/repository"
                  className="input w-full"
                  disabled={isLoading}
                />
                <p className="text-xs text-gray-500 mt-1">
                  Enter the full URL to any public GitHub repository
                </p>
                {githubUrl && !githubUrl.startsWith('https://github.com/') && (
                  <div className="mt-2 text-sm text-red-400 flex items-center">
                    <AlertCircle className="h-4 w-4 mr-1" />
                    Please enter a valid GitHub repository URL
                  </div>
                )}
                {githubUrl && githubUrl.startsWith('https://github.com/') && (
                  <div className="mt-2 text-sm text-green-400 flex items-center">
                    <Check className="h-4 w-4 mr-1" />
                    Valid GitHub repository URL
                  </div>
                )}
              </div>

              {isLoading && processingProgress > 0 && (
                <div className="mt-4 flex flex-col items-center">
                  <div className="relative w-full h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className="absolute top-0 left-0 h-full bg-blue-500 transition-all duration-300 ease-out"
                      style={{ width: `${processingProgress}%` }}
                    />
                  </div>
                  <p className="mt-2 text-sm text-gray-400">
                    {processingProgress < 100
                      ? `Connecting to GitHub (${Math.round(processingProgress)}%)`
                      : 'Connected! Redirecting to analysis...'}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Submit */}
        {!isLoading ? (
          <div className="flex justify-end">
            <button
              type="submit"
              className="btn btn-primary btn-lg"
              disabled={
                (activeTab === 'upload' && files.length === 0) ||
                (activeTab === 'github' && (!githubUrl || !githubUrl.startsWith('https://github.com/')))
              }
            >
              {activeTab === 'upload' ? (
                <>
                  <Upload className="h-4 w-4 mr-2" />
                  Upload and Analyze
                </>
              ) : (
                <>
                  <Github className="h-4 w-4 mr-2" />
                  Analyze Repository
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-center mt-4">
            <p className="text-sm text-gray-400">
              {processingProgress >= 100
                ? 'Analysis started! Redirecting...'
                : 'Starting security analysis...'}
            </p>
          </div>
        )}
      </form>

      {/* Custom Upload Dialog */}
      {showUploadDialog && (
        <div className="fixed inset-0 flex items-center justify-center z-50 bg-black/50">
          <div className="bg-gray-800 p-6 rounded-lg shadow-lg max-w-md w-full mx-4">
            <h3 className="text-lg font-medium text-white mb-4">Choose Upload Type</h3>
            <div className="grid grid-cols-2 gap-4">
              <button
                onClick={() => {
                  document.getElementById('file-upload')?.click();
                  setShowUploadDialog(false);
                }}
                className="p-4 bg-gray-700 hover:bg-gray-600 rounded-lg flex flex-col items-center transition-colors"
              >
                <Upload className="h-8 w-8 text-blue-400 mb-2" />
                <span className="text-sm font-medium text-white">Select Files</span>
                <span className="text-xs text-gray-400 mt-1">Choose individual files</span>
              </button>
              <button
                onClick={() => {
                  document.getElementById('folder-upload')?.click();
                  setShowUploadDialog(false);
                }}
                className="p-4 bg-gray-700 hover:bg-gray-600 rounded-lg flex flex-col items-center transition-colors"
              >
                <FolderOpen className="h-8 w-8 text-blue-400 mb-2" />
                <span className="text-sm font-medium text-white">Select Folder</span>
                <span className="text-xs text-gray-400 mt-1">Choose entire folder</span>
              </button>
            </div>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowUploadDialog(false)}
                className="btn btn-ghost btn-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tips */}
      <div className="card p-4 bg-blue-900/20 border border-blue-800/40">
        <div className="flex">
          <AlertCircle className="h-5 w-5 text-blue-400 mr-3 flex-shrink-0" />
          <div>
            <h4 className="font-medium text-blue-300 mb-1">Tips for better analysis</h4>
            <ul className="text-gray-300 space-y-1 list-disc pl-5">
              <li>Include all related code files for more comprehensive results</li>
              <li>For GitHub repositories, make sure the repository is public</li>
              <li>Analysis may take several minutes depending on code size</li>
              <li>Results are processed by AI models to identify security issues</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}