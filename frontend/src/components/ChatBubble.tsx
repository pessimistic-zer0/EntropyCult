import { ChatMessage } from '../types';

interface Props {
    message: ChatMessage;
    isSelected: boolean;
    onClick: () => void;
}

const ACTION_DOT = {
    allow: 'bg-emerald-500',
    reprompt: 'bg-amber-500',
    sanitize: 'bg-blue-500',
    block: 'bg-red-500',
};

export default function ChatBubble({ message, isSelected, onClick }: Props) {
    const isUser = message.role === 'user';

    return (
        <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
            <div
                onClick={!isUser ? onClick : undefined}
                className={`
          max-w-[85%] rounded-2xl px-4 py-3 cursor-pointer transition-all
          ${isUser
                        ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-br-md'
                        : `glass-card ${isSelected ? 'ring-2 ring-cyan-500/50' : 'hover:bg-slate-700/50'} rounded-bl-md`
                    }
        `}
            >
                {/* Role label */}
                <div className={`text-xs font-medium mb-1 ${isUser ? 'text-cyan-200' : 'text-slate-400'}`}>
                    {isUser ? 'You' : 'Gateway'}
                    {message.response && (
                        <span className={`inline-block w-2 h-2 rounded-full ml-2 ${ACTION_DOT[message.response.action]}`} />
                    )}
                </div>

                {/* Content */}
                <p className={`text-sm whitespace-pre-wrap ${isUser ? 'text-white' : 'text-slate-200'}`}>
                    {message.content}
                </p>

                {/* Timestamp */}
                <div className={`text-xs mt-2 ${isUser ? 'text-cyan-300/60' : 'text-slate-500'}`}>
                    {message.timestamp.toLocaleTimeString()}
                </div>
            </div>
        </div>
    );
}
